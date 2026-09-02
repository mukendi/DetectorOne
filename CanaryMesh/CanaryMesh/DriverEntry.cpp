// Copyright (c) 2026, Simon Ngoy. All rights reserved.
// Use of this source code is governed by a MIT license.
//
// CanaryMesh EDR canary driver entry point.
//
// Current design notes:
//   1. ntifs.h is the single kernel include surface used by this driver.
//   2. Canaries register through DetectorOne IOCTLs instead of exported symbols.
//      MmGetSystemRoutineAddress only resolves ntoskrnl/hal exports.
//   3. One registration IOCTL returns the shared table and EDR callback baselines.
//   4. Dead registration paths were removed.


#include "CanaryMesh.h"

// Shared canary state. DriverEntry owns the storage; other modules use externs from CanaryMesh.h.
CANARY_GLOBAL_STATE g_State = { 0 };
PVOID g_ProcessCallbackTableAddress = NULL;
PVOID g_ImageCallbackTableAddress = NULL;
PVOID g_ThreadCallbackTableAddress = NULL;
volatile LONG HasVotedThisRound = 0;

// DriverEntry
// ============================================================

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    DbgPrint("[CanaryMesh%lu] DriverEntry\n", (ULONG)CANARY_ID);

    // Reset all runtime state before publishing this canary to DetectorOne.
    RtlZeroMemory(&g_State, sizeof(g_State));
    g_State.CanaryId = CANARY_ID;
    g_State.ShouldStop = 0;

    ExInitializeFastMutex(&g_State.AlertLock);
    KeInitializeEvent(&g_State.AlertEvent, NotificationEvent, FALSE);

    DriverObject->DriverUnload = CanaryUnload;

    // Registration returns the shared mesh table and DetectorOne callback baseline.
    status = CanaryRegisterWithDetectorOne(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[CanaryMesh%lu] Registration failed 0x%08X\n",
            (ULONG)CANARY_ID, status);
        return status;
    }

    PCanaryMesh_EDR_CALLBACK_BASELINE baseline = &g_State.Table->CallbackBaseline;

    // Validate the baseline once at startup so Signal A is enabled only for callbacks we can locate.
    if (baseline->Valid) {
        DbgPrint("[CanaryMesh%lu] Callback baseline received:\n", (ULONG)CANARY_ID);
        DbgPrint("[CanaryMesh%lu]   ProcessCallback = %p\n", (ULONG)CANARY_ID, baseline->ProcessCallbackAddress);
        DbgPrint("[CanaryMesh%lu]   ImageCallback   = %p\n", (ULONG)CANARY_ID, baseline->ImageCallbackAddress);
        DbgPrint("[CanaryMesh%lu]   ThreadCallback  = %p\n", (ULONG)CANARY_ID, baseline->ThreadCallbackAddress);

        g_State.SignalAProcessBaselineValid =
            CanaryVerifyCallbackPointerForRoutine(
                L"PsSetCreateProcessNotifyRoutineEx",
                baseline->ProcessCallbackAddress,
                &g_ProcessCallbackTableAddress);
        if (!g_State.SignalAProcessBaselineValid) {
            g_State.SignalAProcessBaselineValid =
                CanaryVerifyCallbackPointerForRoutine(
                    L"PsSetCreateProcessNotifyRoutine",
                    baseline->ProcessCallbackAddress,
                    &g_ProcessCallbackTableAddress);
        }
        g_State.SignalAImageBaselineValid =
            CanaryVerifyCallbackPointerForRoutine(
                L"PsSetLoadImageNotifyRoutine",
                baseline->ImageCallbackAddress,
                &g_ImageCallbackTableAddress);
        g_State.SignalAThreadBaselineValid =
            CanaryVerifyCallbackPointerForRoutine(
                L"PsSetCreateThreadNotifyRoutine",
                baseline->ThreadCallbackAddress,
                &g_ThreadCallbackTableAddress);

        DbgPrint("[CanaryMesh%lu] Signal A baselines: Process=%u Image=%u Thread=%u\n",
            (ULONG)CANARY_ID,
            (ULONG)g_State.SignalAProcessBaselineValid,
            (ULONG)g_State.SignalAImageBaselineValid,
            (ULONG)g_State.SignalAThreadBaselineValid);

        if (!g_State.SignalAProcessBaselineValid &&
            !g_State.SignalAImageBaselineValid &&
            !g_State.SignalAThreadBaselineValid) {
            DbgPrint("[CanaryMesh%lu] WARNING: no callback baseline found; Signal A disabled for this boot\n",
                (ULONG)CANARY_ID);
        }
    }

    // Start the three independent sensors: peer liveness, suspect-driver tracking, and callback health.
    HANDLE hThread = NULL;

    status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS,
        NULL, NULL, NULL, CanaryHeartbeatThread, &g_State);
    if (!NT_SUCCESS(status)) return status;
    ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType,
        KernelMode, (PVOID*)&g_State.HeartbeatThread, NULL);
    ZwClose(hThread);

    status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS,
        NULL, NULL, NULL, CanaryDriverWatchThread, &g_State);
    if (!NT_SUCCESS(status)) return status;
    ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType,
        KernelMode, (PVOID*)&g_State.DriverWatchThread, NULL);
    ZwClose(hThread);

    status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS,
        NULL, NULL, NULL, CanaryCallbackWatchThread, &g_State);
    if (!NT_SUCCESS(status)) return status;
    ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType,
        KernelMode, (PVOID*)&g_State.CallbackWatchThread, NULL);
    ZwClose(hThread);

    DbgPrint("[CanaryMesh%lu] Loaded — three surveillance threads active\n", (ULONG)CANARY_ID);

    return STATUS_SUCCESS;
}

// ============================================================
// CanaryUnload
// ============================================================

VOID CanaryUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrint("[CanaryMesh%lu] Unload requested\n", (ULONG)CANARY_ID);

    // Signal all worker threads before waiting on their referenced thread objects.
    InterlockedExchange(&g_State.ShouldStop, 1);
    KeSetEvent(&g_State.AlertEvent, IO_NO_INCREMENT, FALSE);

    if (g_State.CallbackWatchThread) {
        KeWaitForSingleObject(g_State.CallbackWatchThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_State.CallbackWatchThread);
        g_State.CallbackWatchThread = NULL;
    }

    if (g_State.DriverWatchThread) {
        KeWaitForSingleObject(g_State.DriverWatchThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_State.DriverWatchThread);
        g_State.DriverWatchThread = NULL;
    }

    if (g_State.HeartbeatThread) {
        KeWaitForSingleObject(g_State.HeartbeatThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_State.HeartbeatThread);
        g_State.HeartbeatThread = NULL;
    }

    if (g_State.Table) {
        PCANARY_IDENTITY mySlot = &g_State.Table->Canaries[g_State.CanaryId - 1];
        InterlockedExchange(&mySlot->Status, CANARY_STATUS_DEAD);
        InterlockedDecrement(&g_State.Table->RegisteredCount);
        g_State.Table = NULL;
    }

    DbgPrint("[CanaryMesh%lu] Unloaded safely\n", (ULONG)CANARY_ID);
}


