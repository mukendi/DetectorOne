#include "CanaryMesh.h"

// ============================================================
// CanaryRegisterWithDetectorOne
// ============================================================

NTSTATUS CanaryRegisterWithDetectorOne(IN PDRIVER_OBJECT DriverObject) {
    NTSTATUS status;
    UNICODE_STRING deviceName;
    PFILE_OBJECT    fileObject = NULL;
    PDEVICE_OBJECT  devObject = NULL;

    RtlInitUnicodeString(&deviceName, KRATOS_DEVICE_NAME);

    // Open DetectorOne by device name; a canary cannot operate without the shared EDR control plane.
    status = IoGetDeviceObjectPointer(
        &deviceName,
        FILE_READ_DATA,
        &fileObject,
        &devObject
    );
    if (!NT_SUCCESS(status)) {
        DbgPrint("[CanaryMesh%lu] Cannot open %S Status=0x%08X — is DetectorOne loaded?\n",
            (ULONG)CANARY_ID, KRATOS_DEVICE_NAME, status);
        return status;
    }

    ULONG bufferSize = max(sizeof(KRATOS_REGISTER_REQUEST), sizeof(KRATOS_REGISTER_RESPONSE));

    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, CANARY_POOL_TAG);
    if (!buffer) {
        ObDereferenceObject(fileObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(buffer, bufferSize);

    PKRATOS_REGISTER_REQUEST req = (PKRATOS_REGISTER_REQUEST)buffer;
    req->CanaryId = CANARY_ID;
    req->DriverObjectAddress = (PVOID)DriverObject;
    req->AlertEntryPoint = (PVOID)CanaryReceiveAlert;

    KEVENT event;
    KeInitializeEvent(&event, NotificationEvent, FALSE);

    IO_STATUS_BLOCK ioStatus = { 0 };

    // Use a synchronous internal IOCTL so registration completes before surveillance threads start.
    PIRP irp = IoBuildDeviceIoControlRequest(
        IOCTL_KRATOS_REGISTER,
        devObject,
        buffer, sizeof(KRATOS_REGISTER_REQUEST),
        buffer, sizeof(KRATOS_REGISTER_RESPONSE),
        FALSE,
        &event,
        &ioStatus
    );

    if (!irp) {
        ExFreePoolWithTag(buffer, CANARY_POOL_TAG);
        ObDereferenceObject(fileObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IoCallDriver(devObject, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = ioStatus.Status;
    }

    if (!NT_SUCCESS(status)) {
        DbgPrint("[CanaryMesh%lu] IOCTL_KRATOS_REGISTER failed 0x%08X\n", (ULONG)CANARY_ID, status);
        ExFreePoolWithTag(buffer, CANARY_POOL_TAG);
        ObDereferenceObject(fileObject);
        return status;
    }

    PKRATOS_REGISTER_RESPONSE resp = (PKRATOS_REGISTER_RESPONSE)buffer;

    if (!NT_SUCCESS(resp->Status)) {
        DbgPrint("[CanaryMesh%lu] Registration rejected by DetectorOne 0x%08X\n",
            (ULONG)CANARY_ID, resp->Status);
        ExFreePoolWithTag(buffer, CANARY_POOL_TAG);
        ObDereferenceObject(fileObject);
        return resp->Status;
    }

    // DetectorOne owns this nonpaged shared table. Validate the magic before trusting the pointer.
    PCanaryMesh_CANARY_TABLE table = (PCanaryMesh_CANARY_TABLE)resp->TablePointer;

    if (!table || table->Magic != 0x4B524154) {
        DbgPrint("[CanaryMesh%lu] Invalid table pointer or magic\n", (ULONG)CANARY_ID);
        ExFreePoolWithTag(buffer, CANARY_POOL_TAG);
        ObDereferenceObject(fileObject);
        return STATUS_INVALID_ADDRESS;
    }

    g_State.Table = table;

    // Cache DetectorOne callback addresses and liveness counters for later tamper checks.
    PCanaryMesh_EDR_CALLBACK_BASELINE baseline = &table->CallbackBaseline;
    baseline->ProcessCallbackAddress = resp->ProcessCallbackAddress;
    baseline->ImageCallbackAddress = resp->ImageCallbackAddress;
    baseline->ThreadCallbackAddress = resp->ThreadCallbackAddress;
    baseline->ProcessEventCounter = (volatile LONG64*)resp->ProcessEventCounterPtr;
    baseline->ImageEventCounter = (volatile LONG64*)resp->ImageEventCounterPtr;
    baseline->Valid = TRUE;
    KeQuerySystemTime(&g_State.LivenessBaselineCaptureTime);

    DbgPrint("[CanaryMesh%lu] Registered with DetectorOne — TablePtr=%p\n", (ULONG)CANARY_ID, table);

    ExFreePoolWithTag(buffer, CANARY_POOL_TAG);
    ObDereferenceObject(fileObject);
    return STATUS_SUCCESS;
}


// ============================================================
// CanaryReceiveAlert
// ============================================================

extern "C"
VOID NTAPI CanaryReceiveAlert(
    IN PWSTR            DriverName,
    IN PLARGE_INTEGER   LoadTimestamp,
    IN ULONG            RiskScore
) {
    ExAcquireFastMutex(&g_State.AlertLock);

    // Keep one active incident per canary to avoid mixing driver timelines in the same vote round.
    if (g_State.Alert.Active) {
        DbgPrint("[CanaryMesh%lu] Alert already active for %S — ignoring %S\n",
            (ULONG)CANARY_ID, g_State.Alert.DriverName, DriverName);
        ExReleaseFastMutex(&g_State.AlertLock);
        return;
    }

    // Publish the alert state with interlocked writes because worker threads consume it concurrently.
    InterlockedExchange(&g_State.Alert.Active, 1);
    InterlockedExchange(&g_State.Alert.DriverStillLoaded, 1);
    InterlockedExchange(&g_State.Alert.UnloadDetected, 0);
    InterlockedExchange(&g_State.Alert.CallbackRemovalDetected, 0);
    InterlockedExchange(&g_State.Alert.LivenessDropDetected, 0);
    InterlockedExchange(&g_State.Alert.DetectedSignals, 0);
    g_State.LivenessObservedAfterAlert = FALSE;
    g_State.LastConsensusReportTime.QuadPart = 0;

    RtlStringCchCopyW(g_State.Alert.DriverName,
        ARRAYSIZE(g_State.Alert.DriverName), DriverName);

    g_State.Alert.LoadTimestamp = *LoadTimestamp;
    g_State.Alert.RiskScore = RiskScore;
    KeQuerySystemTime(&g_State.Alert.ActivationTime);

    // Cache DetectorOne callback addresses and liveness counters for later tamper checks.
    PCanaryMesh_EDR_CALLBACK_BASELINE baseline = &g_State.Table->CallbackBaseline;

    // Capture liveness baselines at alert time; later deltas tell us whether callbacks still fire.
    if (baseline->Valid && baseline->ProcessEventCounter) {
        g_State.LivenessProcessBaseline =
            InterlockedAdd64((volatile LONG64*)baseline->ProcessEventCounter, 0);
    }
    if (baseline->Valid && baseline->ImageEventCounter) {
        g_State.LivenessImageBaseline =
            InterlockedAdd64((volatile LONG64*)baseline->ImageEventCounter, 0);
    }

    KeQuerySystemTime(&g_State.LivenessBaselineCaptureTime);

    ExReleaseFastMutex(&g_State.AlertLock);
    KeSetEvent(&g_State.AlertEvent, IO_NO_INCREMENT, FALSE);

    DbgPrint("[CanaryMesh%lu] ALERT RECEIVED Driver=%S LoadTime=%lld Risk=%lu\n",
        (ULONG)CANARY_ID, DriverName, LoadTimestamp->QuadPart, RiskScore);
    DbgPrint("[CanaryMesh%lu]   Baseline: ProcessEvents=%lld ImageEvents=%lld\n",
        (ULONG)CANARY_ID, g_State.LivenessProcessBaseline, g_State.LivenessImageBaseline);
}


NTSTATUS CanaryWaitForHandoff(IN PCanaryMesh_CANARY_TABLE Table) {
    LARGE_INTEGER interval;
    interval.QuadPart = -(200 * 10000LL);
    ULONG elapsed = 0;

    while (elapsed < CanaryMesh_HANDOFF_TIMEOUT_MS) {
        if (InterlockedCompareExchange(&Table->HandoffComplete, 1, 1) == 1)
            return STATUS_SUCCESS;
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
        elapsed += 200;
    }
    return STATUS_TIMEOUT;
}

