// Copyright (c) 2026, Simon Ngoy. All rights reserved.
// Use of this source code is governed by an MIT license.
//
// DetectorOne.cpp - DetectorOne EDR Primary Sensor
//
// Responsibilities:
// 1. Monitoring processes, threads, images, registry
// 2. IAT analysis of loaded drivers
// 3. Canary orchestration (bootstrap + handoff)
// 4. Dispatch of High Risk alerts to the canaries
// 5. Exhibition of the exports necessary for canaries:




#include "header.h"

PDEVICE_OBJECT   g_DeviceObject = NULL;
BOOLEAN          g_SymlinkCreated = FALSE;
const DETECTORONE_DANGEROUS_IMPORT g_DangerousImports[] = {
    { "ZwTerminateProcess",                 75, "PROCESS_KILL"      },
    { "MmMapIoSpace",                       75, "PHYSICAL_MEMORY"   },
    { "MmMapIoSpaceEx",                     65, "PHYSICAL_MEMORY"   },
    { "ZwOpenProcess",                      35, "PROCESS_ACCESS"    },
    { "NtOpenProcess",                      35, "PROCESS_ACCESS"    },
    { "ZwQuerySystemInformation",           30, "PROCESS_ENUM"      },
    { "ZwMapViewOfSection",                 25, "MEMORY_MAPPING"    },
    { "MmMapLockedPagesSpecifyCache",       30, "MEMORY_MAPPING"    },
    { "MmGetPhysicalAddress",               20, "PHYSICAL_MEMORY"   },
    { "PsSetCreateProcessNotifyRoutine",    50, "CALLBACK_MANIP"    },
    { "PsSetCreateProcessNotifyRoutineEx",  50, "CALLBACK_MANIP"    },
    { "PsSetLoadImageNotifyRoutine",        50, "CALLBACK_MANIP"    },
    { "PsSetCreateThreadNotifyRoutine",     50, "CALLBACK_MANIP"    },
    { "ObRegisterCallbacks",                45, "CALLBACK_MANIP"    },
    { "ObUnRegisterCallbacks",              60, "CALLBACK_REMOVAL"  },
    { "__readmsr",                          70, "MSR_ACCESS"        },
    { "__writemsr",                         70, "MSR_ACCESS"        },
    { NULL, 0, NULL }
};

RTL_AVL_TABLE    g_RwxTable;
LIST_ENTRY       g_ProcessList;
LIST_ENTRY       g_ThreadList;
FAST_MUTEX       g_ProcessListLock;
FAST_MUTEX       g_ThreadListLock;
FAST_MUTEX       g_RwxTableLock;
BOOLEAN          g_ProcessCallbackRegistered = FALSE;
BOOLEAN          g_ThreadCallbackRegistered = FALSE;
BOOLEAN          g_ImageLoadCallbackRegistered = FALSE;
BOOLEAN          g_RegistryCallbackRegistered = FALSE;
volatile LONG    g_Unloading = 0;
LARGE_INTEGER    g_RegistryCallbackCookie = { 0 };
volatile LONG64  g_ProcessEventCounter = 0;
volatile LONG64  g_ImageEventCounter = 0;
volatile LONG    g_AlertDispatching = 0;
volatile LONG    HasVotedThisRound = 0;
PDetectorOne_CANARY_TABLE g_CanaryTable = NULL;
KRATOS_SERVICE_ENTRY g_ServiceTable[KRATOS_MAX_SERVICE_ENTRIES] = { 0 };
KRATOS_CANARY_MONITOR_STATE g_CanaryMonitor = { 0 };
FAST_MUTEX            g_ServiceTableLock;
ULONG                 g_ServiceTableIndex = 0;
FAST_MUTEX            g_TelemetryLock;
DETECTORONE_TELEMETRY_EVENT g_TelemetryRing[DETECTORONE_EVENT_RING_SIZE] = { 0 };
ULONG                 g_TelemetryHead = 0;
ULONG                 g_TelemetryCount = 0;
ULONG                 g_TelemetryDropped = 0;
volatile LONG64       g_TelemetrySequence = 0;
const WCHAR* g_CanaryServicePaths[] = {
    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\realtekv",
    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\intelv_mei",
    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\amdv_chip",
};
const ULONG g_CanaryCount = sizeof(g_CanaryServicePaths) / sizeof(g_CanaryServicePaths[0]);




// AVL comparator for RWX region tracking. Entries are keyed by process ID
// then base address so duplicate snapshots collapse deterministically.
RTL_GENERIC_COMPARE_RESULTS CompareRwxEntries(
    PRTL_AVL_TABLE Table, PVOID First, PVOID Second)
{
    UNREFERENCED_PARAMETER(Table);
    auto p1 = (PRWX_REGION_ENTRY)First;
    auto p2 = (PRWX_REGION_ENTRY)Second;

    if (p1->ProcessId < p2->ProcessId) return GenericLessThan;
    if (p1->ProcessId > p2->ProcessId) return GenericGreaterThan;
    if (p1->BaseAddress < p2->BaseAddress) return GenericLessThan;
    if (p1->BaseAddress > p2->BaseAddress) return GenericGreaterThan;
    return GenericEqual;
}

// Nonpaged AVL allocator because callback paths may run in kernel contexts
// where pageable allocations would be unsafe.
PVOID AllocateAvl(PRTL_AVL_TABLE Table, CLONG ByteSize) {
    UNREFERENCED_PARAMETER(Table);
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, ByteSize, 'avlR');
}

VOID FreeAvl(PRTL_AVL_TABLE Table, PVOID Buffer) {
    UNREFERENCED_PARAMETER(Table);
    ExFreePool(Buffer);
}


extern "C"
// Driver bootstrap entry point. Keep initialization order explicit: shared state,
// device/IOCTL surface, kernel callbacks, then canary startup.
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING deviceName, symlinkName;
    RtlInitUnicodeString(&deviceName, DETECTOR_DEVICE_NAME);
    RtlInitUnicodeString(&symlinkName, DETECTOR_SYMLINK_NAME);

    
    DbgPrint("=========================================\n");
    DbgPrint("[+] DetectorOne EDR v1.0\n");

    // Initialize shared telemetry stores before callbacks can write to them.
    ExInitializeFastMutex(&g_RwxTableLock);
    RtlInitializeGenericTableAvl(&g_RwxTable, CompareRwxEntries, AllocateAvl, FreeAvl, NULL);
    InitializeListHead(&g_ProcessList);
    InitializeListHead(&g_ThreadList);
    ExInitializeFastMutex(&g_ThreadListLock);
    ExInitializeFastMutex(&g_ProcessListLock);
    ExInitializeFastMutex(&g_ServiceTableLock);
    ExInitializeFastMutex(&g_TelemetryLock);

    // Create the kernel device CanaryMesh opens to register itself.
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject
    );
    if (!NT_SUCCESS(status)) {
        DbgPrint("[DetectorOne] IoCreateDevice failed 0x%08X\n", status);
        // Callback/device cleanup is handled by the failure path below.
        return status;
    }

    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (NT_SUCCESS(status)) {
        g_SymlinkCreated = TRUE;
    }
    // Expose the IOCTL surface used by canaries to register and retrieve
    // the shared table plus DetectorOne callback baseline.
    DriverObject->MajorFunction[IRP_MJ_CREATE] =
        DetectorOneDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] =
        DetectorOneDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
        DetectorOneDispatchIoctl;

    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrint("[DetectorOne] Device created: %S\n", DETECTOR_DEVICE_NAME);

    

    // Process callback gives local process inventory and a liveness counter.
    status = PsSetCreateProcessNotifyRoutineEx(
        DetectorOneCreateProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[DetectorOne] Failed process notify: 0x%X\n", status);
        return status;
    }
    g_ProcessCallbackRegistered = TRUE;

    // Thread callback adds execution telemetry around suspicious driver loads.
    status = PsSetCreateThreadNotifyRoutine(DetectorOneCreateThreadNotify);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[DetectorOne] Failed thread notify: 0x%X\n", status);
        PsSetCreateProcessNotifyRoutineEx(
            DetectorOneCreateProcessNotify, TRUE);
        g_ProcessCallbackRegistered = FALSE;
        return status;
    }
    g_ThreadCallbackRegistered = TRUE;

    // Image callback is the post-load BYOVD detection path for kernel .sys images.
    status = PsSetLoadImageNotifyRoutine(DetectorOneLoadImageNotify);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[DetectorOne] Failed image notify: 0x%X\n", status);
        PsRemoveCreateThreadNotifyRoutine(DetectorOneCreateThreadNotify);
        PsSetCreateProcessNotifyRoutineEx(
            DetectorOneCreateProcessNotify, TRUE);
        g_ThreadCallbackRegistered = FALSE;
        g_ProcessCallbackRegistered = FALSE;
        return status;
    }
    g_ImageLoadCallbackRegistered = TRUE;

    {
        // Registry callback is the pre-load enforcement path: it can deny
        // ImagePath writes before NtLoadDriver consumes the service key.
        UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"370030.4210");
        status = CmRegisterCallbackEx(DetectorOneRegistryCallback,
            &altitude, DriverObject, NULL,
            &g_RegistryCallbackCookie, NULL);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[DetectorOne] Failed registry callback: 0x%X\n", status);
            PsRemoveLoadImageNotifyRoutine(DetectorOneLoadImageNotify);
            PsRemoveCreateThreadNotifyRoutine(
                DetectorOneCreateThreadNotify);
            PsSetCreateProcessNotifyRoutineEx(
                DetectorOneCreateProcessNotify, TRUE);
            g_ImageLoadCallbackRegistered = FALSE;
            g_ThreadCallbackRegistered = FALSE;
            g_ProcessCallbackRegistered = FALSE;
            return status;
        }
        g_RegistryCallbackRegistered = TRUE;
    }

    DbgPrint("[DetectorOne] Callbacks registered\n");
    // Start canaries only after DetectorOne callbacks are installed, otherwise
    // the callback baseline exported to the mesh would be incomplete.
    status = DetectorOneBootstrapCanaries();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[DetectorOne] WARNING: Canary bootstrap failed "
            "0x%08X - continuing without canaries\n", status);
        status = STATUS_SUCCESS;
    }

    DbgPrint("[DetectorOne] Loaded\n");

    DriverObject->DriverUnload = DetectorOneUnloadDriver;
    return status;
}

// Ordered shutdown path. Canaries are stopped first because they hold pointers
// into DetectorOne-owned shared state and callback baselines.
VOID DetectorOneUnloadDriver(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    NTSTATUS status;

    DbgPrint("[DetectorOne] Unload requested\n");
    InterlockedExchange(&g_Unloading, 1);

    // Tell canaries to stop using the shared table before DetectorOne unloads them.
    if (g_CanaryTable) {
        InterlockedExchange(&g_CanaryTable->HandoffComplete, 0);
        //InterlockedExchange(&g_CanaryTable->IsUnloading, 1);

        DbgPrint("[DetectorOne] ShutdownPending signaled to canaries\n");
        // Give canary worker threads a short window to leave their current
        // polling iteration before ZwUnloadDriver is called on their services.
        LARGE_INTEGER delay;
        delay.QuadPart = -(200 * 10000LL); // 200ms
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
    // ZwUnloadDriver is synchronous: once it returns, the canary unload routine
    // has completed and its worker threads should no longer touch shared state.
    static const WCHAR* CanaryServicePaths[] = {
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\amdv_chip",
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\intelv_mei",
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\realtekv",
    };

    for (ULONG i = 0; i < ARRAYSIZE(CanaryServicePaths); i++) {
        UNICODE_STRING servicePath;
        RtlInitUnicodeString(&servicePath, CanaryServicePaths[i]);

        DbgPrint("[DetectorOne] Unloading canary: %wZ\n", &servicePath);

        status = ZwUnloadDriver(&servicePath);
        if (!NT_SUCCESS(status)) {
            // A missing canary is not fatal during DetectorOne shutdown.
            DbgPrint("[DetectorOne] Canary unload returned 0x%08X "
                "(may already be unloaded) Path=%wZ\n",
                status, &servicePath);
        }
        else {
            DbgPrint("[DetectorOne] Canary unloaded safely: %wZ\n",
                &servicePath);
        }
    }

    DbgPrint("[DetectorOne] All canaries unloaded - "
        "proceeding with own cleanup\n");

    // Remove callbacks in reverse operational order so no new telemetry arrives
    // while shared state is being released.
    if (g_ImageLoadCallbackRegistered) {
        status = PsRemoveLoadImageNotifyRoutine(DetectorOneLoadImageNotify);
        if (NT_SUCCESS(status))
            g_ImageLoadCallbackRegistered = FALSE;
        else
            DbgPrint("[DetectorOne] Remove image notify failed 0x%X\n",
                status);
    }

    if (g_ProcessCallbackRegistered) {
        status = PsSetCreateProcessNotifyRoutineEx(
            DetectorOneCreateProcessNotify, TRUE);
        if (NT_SUCCESS(status))
            g_ProcessCallbackRegistered = FALSE;
        else
            DbgPrint("[DetectorOne] Remove process notify failed 0x%X\n",
                status);
    }

    if (g_ThreadCallbackRegistered) {
        status = PsRemoveCreateThreadNotifyRoutine(
            DetectorOneCreateThreadNotify);
        if (NT_SUCCESS(status))
            g_ThreadCallbackRegistered = FALSE;
        else
            DbgPrint("[DetectorOne] Remove thread notify failed 0x%X\n",
                status);
    }

    if (g_RegistryCallbackRegistered) {
        status = CmUnRegisterCallback(g_RegistryCallbackCookie);
        if (NT_SUCCESS(status)) {
            g_RegistryCallbackRegistered = FALSE;
            g_RegistryCallbackCookie.QuadPart = 0;
        }
        else {
            DbgPrint("[DetectorOne] Remove registry callback failed 0x%X\n",
                status);
        }
    }
    // At this point canaries should have stopped touching the shared table.
    if (g_CanaryTable) {
        ExFreePoolWithTag(g_CanaryTable, 'KRCT');
        g_CanaryTable = NULL;
        DbgPrint("[DetectorOne] Canary table freed\n");
    }


    // Final cleanup of device, symbolic link, and nonpaged pools.
    if (g_SymlinkCreated) {
        UNICODE_STRING symlinkName = RTL_CONSTANT_STRING(DETECTOR_SYMLINK_NAME);
        IoDeleteSymbolicLink(&symlinkName);
    }
    if (g_SymlinkCreated) {
        UNICODE_STRING symlinkName;
        RtlInitUnicodeString(&symlinkName, DETECTOR_SYMLINK_NAME);
        IoDeleteSymbolicLink(&symlinkName);
        g_SymlinkCreated = FALSE;
    }

    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    if (g_CanaryTable) {
        ExFreePoolWithTag(g_CanaryTable, 'KRCT');
        g_CanaryTable = NULL;
    }



    // Release process/thread/RWX telemetry accumulated while the driver ran.
    ExAcquireFastMutex(&g_ThreadListLock);
    while (!IsListEmpty(&g_ThreadList)) {
        PLIST_ENTRY e = RemoveHeadList(&g_ThreadList);
        PTHREAD_ENTRY t = CONTAINING_RECORD(e, THREAD_ENTRY, ThreadListEntry);
        ExFreePool(t);
    }
    ExReleaseFastMutex(&g_ThreadListLock);

    ExAcquireFastMutex(&g_ProcessListLock);
    while (!IsListEmpty(&g_ProcessList)) {
        PLIST_ENTRY e = RemoveHeadList(&g_ProcessList);
        PPROCESS_ENTRY p =
            CONTAINING_RECORD(e, PROCESS_ENTRY, ProcessListEntry);
        if (p->ImageFileName.Buffer) {
            ExFreePoolWithTag(p->ImageFileName.Buffer, 'FgmI');
            p->ImageFileName.Buffer = NULL;
        }
        ExFreePoolWithTag(p, POOL_TAG);
    }
    ExReleaseFastMutex(&g_ProcessListLock);

    ExAcquireFastMutex(&g_RwxTableLock);
    while (!RtlIsGenericTableEmptyAvl(&g_RwxTable)) {
        PVOID e = RtlGetElementGenericTableAvl(&g_RwxTable, 0);
        if (e) RtlDeleteElementGenericTableAvl(&g_RwxTable, e);
    }
    ExReleaseFastMutex(&g_RwxTableLock);

    DbgPrint("[DetectorOne] Unloaded\n");
}


// DetectorOneLoadImageNotify
// BYOVD Detection Main Entry Point


