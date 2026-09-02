#include "header.h"

// DetectorOne canary bootstrap, dispatch and monitor helpers.

ULONG DetectorOneCalculateQuorum(IN ULONG TotalCanaries) {
    if (TotalCanaries <= 2) return TotalCanaries;
    return (TotalCanaries / 2) + 1;
}

// Allocate the shared canary table, publish the callback baseline, and load
// each canary service. The mesh is intentionally started by DetectorOne so it
// observes the exact callbacks installed by this boot instance.
NTSTATUS DetectorOneBootstrapCanaries() {

    DbgPrint("[DetectorOne] Bootstrap: allocating canary table "
        "Count=%lu\n", g_CanaryCount);

    // Shared nonpaged state read by DetectorOne and every registered canary.
    g_CanaryTable = (PDetectorOne_CANARY_TABLE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(DetectorOne_CANARY_TABLE),
        'KRCT'
    );
    if (!g_CanaryTable) return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(g_CanaryTable, sizeof(DetectorOne_CANARY_TABLE));
    g_CanaryTable->Magic = 0x4B524154;
    g_CanaryTable->Version = 1;
    g_CanaryTable->ExpectedCount = g_CanaryCount;
    g_CanaryTable->QuorumRequired =
        DetectorOneCalculateQuorum(g_CanaryCount);
    g_CanaryTable->HandoffComplete = 0;

    // Pre-fill the baseline callbacks in the table
    // (the canaries will be able to read it directly after handoff)
    g_CanaryTable->CallbackBaseline.ProcessCallbackAddress =
        (PVOID)DetectorOneCreateProcessNotify;
    g_CanaryTable->CallbackBaseline.ImageCallbackAddress =
        (PVOID)DetectorOneLoadImageNotify;
    g_CanaryTable->CallbackBaseline.ThreadCallbackAddress =
        (PVOID)DetectorOneCreateThreadNotify;
    g_CanaryTable->CallbackBaseline.ProcessEventCounter =
        &g_ProcessEventCounter;
    g_CanaryTable->CallbackBaseline.ImageEventCounter =
        &g_ImageEventCounter;
    g_CanaryTable->CallbackBaseline.Valid = TRUE;
    KeQuerySystemTime(
        &g_CanaryTable->CallbackBaseline.BaselineCaptureTime);

    DbgPrint("[DetectorOne] Bootstrap: callback baseline pre-filled\n");
    DbgPrint("[DetectorOne] Bootstrap: launching %lu canaries "
        "Quorum=%lu\n",
        g_CanaryCount, g_CanaryTable->QuorumRequired);

    // Load each configured canary driver service.
    for (ULONG i = 0; i < g_CanaryCount; i++) {
        UNICODE_STRING servicePath;
        RtlInitUnicodeString(&servicePath, g_CanaryServicePaths[i]);

        NTSTATUS status = ZwLoadDriver(&servicePath);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[DetectorOne] Bootstrap: failed to load canary %lu "
                "Path=%wZ Status=0x%08X\n",
                i + 1, &servicePath, status);
        }
        else {
            DbgPrint("[DetectorOne] Bootstrap: canary %lu load requested "
                "Path=%wZ\n", i + 1, &servicePath);
        }
    }

    NTSTATUS status =
        DetectorOneWaitForCanaryRegistrations(DetectorOne_CANARY_LOAD_TIMEOUT_MS);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[DetectorOne] Bootstrap: timeout — "
            "registered %ld/%lu canaries\n",
            g_CanaryTable->RegisteredCount,
            g_CanaryTable->ExpectedCount);
    }

    DetectorOneHandoffToCanaries();

    return STATUS_SUCCESS;
}

NTSTATUS DetectorOneWaitForCanaryRegistrations(IN ULONG TimeoutMs) {
    LARGE_INTEGER interval;
    interval.QuadPart = -(200 * 10000LL);
    ULONG elapsed = 0;

    while (elapsed < TimeoutMs) {
        if (g_CanaryTable->RegisteredCount >=
            (LONG)g_CanaryTable->ExpectedCount) {
            DbgPrint("[DetectorOne] Bootstrap: all canaries registered "
                "Count=%ld\n", g_CanaryTable->RegisteredCount);
            return STATUS_SUCCESS;
        }
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
        elapsed += 200;
    }
    return STATUS_TIMEOUT;
}

// Finalize canary startup. Once HandoffComplete is set, canary worker threads
// may start voting and monitoring DetectorOne liveness.
VOID DetectorOneHandoffToCanaries() {
    LONG registered = g_CanaryTable->RegisteredCount;

    // Recalculate the quorum using the canaries actually registered
    g_CanaryTable->QuorumRequired =
        DetectorOneCalculateQuorum((ULONG)registered);

    // Report the handoff, the canaries can start their threads
    InterlockedExchange(&g_CanaryTable->HandoffComplete, 1);

    DbgPrint("[DetectorOne] Handoff complete: "
        "Canaries=%ld Quorum=%lu — P2P mode active\n",
        registered, g_CanaryTable->QuorumRequired);
}


// Alert dispatch to canaries
// Called from DetectorOneLoadImageNotify when Risk >= 100

VOID DetectorOneDispatchAlertToCanaries(
    IN PUNICODE_STRING  DriverName,
    IN PLARGE_INTEGER   LoadTimestamp,
    IN ULONG            RiskScore
) {
    if (!g_CanaryTable ||
        !g_CanaryTable->HandoffComplete ||
        !g_CanaryTable->RegisteredCount) {
        DbgPrint("[DetectorOne] No active canaries for alert dispatch\n");
        return;
    }

    WCHAR driverNameW[260] = { 0 };
    if (DriverName && DriverName->Buffer && DriverName->Length > 0) {
        SIZE_T copyLen = min(DriverName->Length / sizeof(WCHAR),
            ARRAYSIZE(driverNameW) - 1);
        RtlCopyMemory(driverNameW, DriverName->Buffer,
            copyLen * sizeof(WCHAR));
    }

    DbgPrint("[DetectorOne] Dispatching alert to %ld canaries: "
        "Driver=%wZ Risk=%lu\n",
        g_CanaryTable->RegisteredCount, DriverName, RiskScore);

    // Call the entry point of each registered canary
    for (ULONG i = 0; i < DetectorOne_MAX_CANARIES; i++) {
        PCANARY_IDENTITY slot = &g_CanaryTable->Canaries[i];

        if (slot->CanaryId == 0 ||
            slot->Status == CANARY_STATUS_DEAD ||
            !slot->AlertEntryPoint) {
            continue;
        }

        // A canary is an independent defensive component; isolate failures so
        // one bad canary does not break alert delivery to the rest of the mesh.
        __try {
            FN_CanaryReceiveAlert fnAlert =
                (FN_CanaryReceiveAlert)slot->AlertEntryPoint;
            fnAlert(driverNameW, LoadTimestamp, RiskScore);

            DbgPrint("[DetectorOne] Alert dispatched to Canary%lu\n",
                slot->CanaryId);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[DetectorOne] Exception dispatching to Canary%lu: "
                "0x%08X\n", slot->CanaryId, GetExceptionCode());
            // Mark the canary as a suspect if the call fails
            InterlockedExchange(&slot->Status, CANARY_STATUS_SUSPECTED);
        }
    }
}


VOID KratosDispatchAlertToCanaries(IN PUNICODE_STRING  DriverName,IN PLARGE_INTEGER LoadTimestamp,IN ULONG  RiskScore) {
    if (!g_CanaryTable ||
        !g_CanaryTable->HandoffComplete ||
        !g_CanaryTable->RegisteredCount) {
        DbgPrint("[DetectorOne] No active canaries for alert dispatch\n");
        return;
    }
    // Copy the driver name into a stable null-terminated buffer for canaries.
    WCHAR driverNameW[260] = { 0 };
    if (DriverName && DriverName->Buffer && DriverName->Length > 0) {
        SIZE_T copyLen = min(
            DriverName->Length / sizeof(WCHAR),
            ARRAYSIZE(driverNameW) - 1
        );
        RtlCopyMemory(driverNameW, DriverName->Buffer,
            copyLen * sizeof(WCHAR));
    }

    DbgPrint("[DetectorOne] Dispatching alert to %ld canaries: "
        "Driver=%wZ Risk=%lu\n",
        g_CanaryTable->RegisteredCount,
        DriverName, RiskScore);

    // Call each registered canary export directly from kernel mode.
    for (ULONG i = 0; i < DetectorOne_MAX_CANARIES; i++) {
        PCANARY_IDENTITY slot = &g_CanaryTable->Canaries[i];

        if (slot->CanaryId == 0 ||
            slot->Status == CANARY_STATUS_DEAD ||
            !slot->AlertEntryPoint) {
            continue;
        }

        // A canary is an independent defensive component; isolate failures so
        // one bad canary does not break alert delivery to the rest of the mesh.
        __try {
            FN_CanaryReceiveAlert fnAlert =
                (FN_CanaryReceiveAlert)slot->AlertEntryPoint;

            fnAlert(driverNameW, LoadTimestamp, RiskScore);

            DbgPrint("[DetectorOne] Alert dispatched to Canary%lu\n",
                slot->CanaryId);

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[DetectorOne] Exception dispatching to "
                "Canary%lu: 0x%08X\n",
                slot->CanaryId, GetExceptionCode());

            // Mark the canary as suspect if its alert entry point faults.
            InterlockedExchange(&slot->Status, CANARY_STATUS_SUSPECTED);
        }
    }
}

// IOCTL registration entry point used by CanaryMesh. DetectorOne validates the
// canary identity and returns the shared table plus callback/liveness baseline.
NTSTATUS NTAPI DetectorOneRegisterCanary(
    IN ULONG    CanaryId,
    IN PVOID    DriverObjectAddress,
    IN PVOID    AlertEntryPoint
) {
    if (!g_CanaryTable)
        return STATUS_NOTHING_TO_TERMINATE;
    if (CanaryId == 0 || CanaryId > DetectorOne_MAX_CANARIES)
        return STATUS_INVALID_PARAMETER;

    PCANARY_IDENTITY slot = &g_CanaryTable->Canaries[CanaryId - 1];

    if (slot->CanaryId != 0) {
        DbgPrint("[DetectorOne] Duplicate canary registration Id=%lu\n",
            CanaryId);
        return STATUS_OBJECT_NAME_COLLISION;
    }

    slot->CanaryId = CanaryId;
    slot->DriverObjectAddress = DriverObjectAddress;
    slot->AlertEntryPoint = AlertEntryPoint;
    slot->RegistrationPid =
        (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    slot->Status = CANARY_STATUS_ALIVE;
    KeQuerySystemTime(&slot->RegistrationTime);
    InterlockedExchange64(&slot->LastHeartbeatTime,
        (LONG64)KeQueryInterruptTime());

    LONG count = InterlockedIncrement(&g_CanaryTable->RegisteredCount);
    InterlockedIncrement(&g_CanaryTable->AliveCount);

    DbgPrint("[DetectorOne] Canary registered Id=%lu "
        "DriverObj=%p AlertEntry=%p Count=%ld/%lu\n",
        CanaryId, DriverObjectAddress, AlertEntryPoint,
        count, g_CanaryTable->ExpectedCount);

    return STATUS_SUCCESS;
}


// Capture a canary health baseline at handoff time.
// The monitor compares live state against this baseline during alerts.
// Refresh the callback baseline after DetectorOne callbacks are installed and
// before canaries begin active monitoring.
VOID KratosSnapshotCanaryBaseline()
{
    if (!g_CanaryTable) return;

    for (ULONG i = 0; i < g_CanaryTable->ExpectedCount; i++) {
        PCANARY_IDENTITY slot = &g_CanaryTable->Canaries[i];
        if (!slot->CanaryId) continue;

        PKRATOS_CANARY_HEALTH_SNAPSHOT snap = &g_CanaryMonitor.Baseline[i];

        snap->CanaryId = slot->CanaryId;
        snap->LastHeartbeatTime = slot->LastHeartbeatTime;
        snap->HeartbeatSequence = slot->HeartbeatSequence;
        snap->Status = (CANARY_STATUS)slot->Status;
        snap->PresentInModuleList = TRUE; // Expected at bootstrap time

        DbgPrint("[DetectorOne] Canary baseline: Id=%lu HB=%lld Seq=%ld\n",
            snap->CanaryId,
            snap->LastHeartbeatTime,
            snap->HeartbeatSequence);
    }

    KeQuerySystemTime(&g_CanaryMonitor.BaselineCaptureTime);
}


// Check whether a canary is still present in PsLoadedModuleList.
BOOLEAN KratosIsCanaryStillLoaded(IN ULONG CanaryId)
{
    // CanaryId-to-service-name lookup table.
    static const WCHAR* g_CanaryServiceNames[] = {
        NULL,           // Index 0 is unused
        L"realtekv",    // Canary 1
        L"intelv_mei",  // Canary 2
        L"amdv_chip",   // Canary 3
        L"kbdhid_v",    // Optional Canary 4
        L"storahci_v",  // Optional Canary 5
    };

    if (CanaryId == 0 || CanaryId >= ARRAYSIZE(g_CanaryServiceNames)) {
        return FALSE;
    }

    PCWSTR serviceName = g_CanaryServiceNames[CanaryId];
    if (!serviceName) return FALSE;

    BOOLEAN found = FALSE;

    __try {
        KeEnterCriticalRegion();
        BOOLEAN acquired = ExAcquireResourceSharedLite(&PsLoadedModuleResource, FALSE);

        if (!acquired) {
            KeLeaveCriticalRegion();
            return TRUE;
        }

        PLIST_ENTRY entry = PsLoadedModuleList.Flink;
        while (entry && entry != &PsLoadedModuleList) {
            PKLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(entry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            if (mod->BaseDllName.Buffer && mod->BaseDllName.Length > 0) {
                UNICODE_STRING targetName;
                RtlInitUnicodeString(&targetName, serviceName);
                if (RtlEqualUnicodeString(&mod->BaseDllName, &targetName, TRUE)) {
                    found = TRUE;
                    break;
                }
            }
            entry = entry->Flink;
        }

        ExReleaseResourceLite(&PsLoadedModuleResource);
        KeLeaveCriticalRegion();

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return TRUE; // Fail open if PsLoadedModuleList traversal faults
    }

    return found;
}


// DetectorOne-side canary health monitor.
// Background monitor for canary health. Loss of canaries during an active alert
// is itself suspicious because BYOVD attacks often target defensive components.
VOID KratosCanaryMonitorThread(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    DbgPrint("[DetectorOne] Canary monitor thread started\n");

    while (!g_CanaryMonitor.ShouldStop) {

        // Grace period handling before canary health enforcement starts.
        if (g_CanaryMonitor.AlertPhaseActive && g_CanaryMonitor.AlertGracePeriodEnd.QuadPart != 0) {
            LARGE_INTEGER now;
            KeQuerySystemTime(&now);

            // The bootstrap grace period elapsed; start normal monitoring.
            if (now.QuadPart >= g_CanaryMonitor.AlertGracePeriodEnd.QuadPart) {
                InterlockedExchange(&g_CanaryMonitor.AlertPhaseActive, 0);
                InterlockedExchange(&g_CanaryMonitor.CanaryKillDetected, 0);
                g_CanaryMonitor.AlertGracePeriodEnd.QuadPart = 0;
                DbgPrint("[DetectorOne] Alert grace period ended. Normal polling resumed.\n");
            }
        }
        // Poll periodically while keeping unload responsive.
        ULONG intervalMs = g_CanaryMonitor.AlertPhaseActive ? 1000 : 5000;
        LARGE_INTEGER delay;
        delay.QuadPart = -(LONGLONG)(intervalMs * 10000LL);
        KeDelayExecutionThread(KernelMode, FALSE, &delay);

        if (!g_CanaryTable || g_CanaryMonitor.ShouldStop) break;

        ULONG aliveBefore = 0;
        ULONG aliveNow = 0;
        BOOLEAN anomalyDetected = FALSE;

        for (ULONG i = 0; i < g_CanaryTable->ExpectedCount; i++) {
            PCANARY_IDENTITY slot = &g_CanaryTable->Canaries[i];
            if (!slot->CanaryId) continue;

            PKRATOS_CANARY_HEALTH_SNAPSHOT snap = &g_CanaryMonitor.Baseline[i];

            // Check heartbeat freshness.
            LONG64 nowInt = (LONG64)KeQueryInterruptTime();
            LONG64 elapsed = nowInt - slot->LastHeartbeatTime;
            LONGLONG elapsedMs = elapsed / 10000;

            // Check that the canary driver is still loaded.
            BOOLEAN stillLoaded = KratosIsCanaryStillLoaded(slot->CanaryId);

            // Check that the heartbeat sequence is still advancing.
            BOOLEAN sequenceProgresses = (slot->HeartbeatSequence > snap->HeartbeatSequence);

            if (snap->Status == CANARY_STATUS_ALIVE) {
                aliveBefore++;
            }
            // Update the shared health view used by quorum decisions.
            if (!stillLoaded) {
                DbgPrint("[DetectorOne] CRITICAL: Canary%lu UNLOADED from PsLoadedModuleList!\n", slot->CanaryId);
                InterlockedExchange((PLONG)&slot->Status, CANARY_STATUS_DEAD);
                anomalyDetected = TRUE;

            }
            else if (elapsedMs > 10000 && !sequenceProgresses) {
                DbgPrint("[DetectorOne] WARNING: Canary%lu heartbeat frozen ElapsedMs=%lld\n", slot->CanaryId, elapsedMs);
                InterlockedExchange((PLONG)&slot->Status, CANARY_STATUS_SUSPECTED);
                anomalyDetected = TRUE;

            }
            else {
                snap->LastHeartbeatTime = slot->LastHeartbeatTime;
                snap->HeartbeatSequence = slot->HeartbeatSequence;
                snap->Status = CANARY_STATUS_ALIVE;
                aliveNow++;
            }
        }
        // Global health decision for the mesh.
        if (anomalyDetected && g_CanaryMonitor.AlertPhaseActive) {

            if (!g_CanaryMonitor.CanaryKillDetected) {
                InterlockedExchange(&g_CanaryMonitor.CanaryKillDetected, 1);

                DbgPrint("[DetectorOne] *** CANARY KILL DETECTED DURING ALERT PHASE ***\n");
                DbgPrint("[DetectorOne]   Alive before: %lu -> Alive now: %lu\n", aliveBefore, aliveNow);
                DbgPrint("[DetectorOne]   Pattern: ATTACKER TARGETING CANARIES FIRST\n");

                KratosRaiseImmediateAlert(
                    ALERT_PREEMPTIVE_CANARY_KILL,
                    aliveNow,
                    g_CanaryTable->ExpectedCount
                );
            }

        }
        else if (anomalyDetected && !g_CanaryMonitor.AlertPhaseActive) {
            DbgPrint("[DetectorOne] WARNING: Canary anomaly outside alert phase — monitoring\n");
        }
    }

    DbgPrint("[DetectorOne] Canary monitor thread stopping\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}


// Emit an immediate DetectorOne-side alert when consensus is unavailable.
VOID KratosRaiseImmediateAlert(
    IN KRATOS_IMMEDIATE_ALERT_TYPE  AlertType,
    IN ULONG                        AliveCount,
    IN ULONG                        ExpectedCount)
{
    DbgPrint("\n");
    DbgPrint("[DetectorOne] ======================================\n");
    DbgPrint("[DetectorOne] *** IMMEDIATE ALERT - NO CONSENSUS ***\n");
    DbgPrint("[DetectorOne] Type    : %lu\n", (ULONG)AlertType);
    DbgPrint("[DetectorOne] Alive   : %lu / %lu canaries\n", AliveCount, ExpectedCount);
    DbgPrint("[DetectorOne] Pattern : Attacker neutralizing detection mesh before targeting EDR\n");
    DbgPrint("[DetectorOne] Action  : Transmit telemetry NOW\n");
    DbgPrint("[DetectorOne] ======================================\n");
    DbgPrint("\n");

}
