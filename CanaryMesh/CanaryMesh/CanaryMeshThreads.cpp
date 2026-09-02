#include "CanaryMesh.h"

// ============================================================
// Callback watch thread - Signal A and Signal B.
// ============================================================

VOID CanaryCallbackWatchThread(PVOID Context) {
    UNREFERENCED_PARAMETER(Context);

    DbgPrint("[CanaryMesh%lu] Callback watch thread started\n", (ULONG)CANARY_ID);

    LARGE_INTEGER interval;
    interval.QuadPart = -(LONGLONG)(CanaryMesh_CALLBACK_CHECK_INTERVAL_MS * 10000);

    while (!g_State.ShouldStop) {

        LARGE_INTEGER timeout;
        timeout.QuadPart = -(LONGLONG)(CanaryMesh_ALERT_WINDOW_MS * 10000);

        // Workers sleep until DetectorOne dispatches a suspect-driver alert.
        NTSTATUS waitStatus = KeWaitForSingleObject(
            &g_State.AlertEvent, Executive, KernelMode, FALSE, &timeout);

        if (g_State.ShouldStop) break;

        if (waitStatus == STATUS_TIMEOUT) {
            if (g_State.Alert.Active)
                InterlockedExchange(&g_State.Alert.Active, 0);
            continue;
        }

        DbgPrint("[CanaryMesh%lu] Callback watch activated\n", (ULONG)CANARY_ID);

        while (!g_State.ShouldStop && g_State.Alert.Active) {

            if (!CanaryIsSuspectDriverLoaded(g_State.Alert.DriverName)) {
                DbgPrint("[CanaryMesh%lu] Callback watch stopped: suspect driver no longer loaded (%S)\n",
                    (ULONG)CANARY_ID, g_State.Alert.DriverName);
                break;
            }

            PCanaryMesh_EDR_CALLBACK_BASELINE baseline = &g_State.Table->CallbackBaseline;

            if (!baseline->Valid) {
                KeDelayExecutionThread(KernelMode, FALSE, &interval);
                continue;
            }

            // Signal A is structural: the EDR callback pointer disappeared from the kernel table.
            BOOLEAN signalAEnabled =
                g_State.SignalAProcessBaselineValid ||
                g_State.SignalAImageBaselineValid ||
                g_State.SignalAThreadBaselineValid;

            if (signalAEnabled) {
                BOOLEAN processCallbackPresent = TRUE;
                BOOLEAN imageCallbackPresent = TRUE;
                BOOLEAN threadCallbackPresent = TRUE;

                if (g_State.SignalAProcessBaselineValid) {
                    processCallbackPresent = CanaryVerifyCallbackPointerForRoutine(
                        L"PsSetCreateProcessNotifyRoutineEx",
                        baseline->ProcessCallbackAddress,
                        &g_ProcessCallbackTableAddress);
                    if (!processCallbackPresent) {
                        processCallbackPresent = CanaryVerifyCallbackPointerForRoutine(
                            L"PsSetCreateProcessNotifyRoutine",
                            baseline->ProcessCallbackAddress,
                            &g_ProcessCallbackTableAddress);
                    }
                }

                if (g_State.SignalAImageBaselineValid) {
                    imageCallbackPresent = CanaryVerifyCallbackPointerForRoutine(
                        L"PsSetLoadImageNotifyRoutine",
                        baseline->ImageCallbackAddress,
                        &g_ImageCallbackTableAddress);
                }

                if (g_State.SignalAThreadBaselineValid) {
                    threadCallbackPresent = CanaryVerifyCallbackPointerForRoutine(
                        L"PsSetCreateThreadNotifyRoutine",
                        baseline->ThreadCallbackAddress,
                        &g_ThreadCallbackTableAddress);
                }

                if (!processCallbackPresent || !imageCallbackPresent || !threadCallbackPresent) {
                    if (!g_State.Alert.CallbackRemovalDetected) {
                        InterlockedExchange(&g_State.Alert.CallbackRemovalDetected, 1);
                        KeQuerySystemTime(&g_State.Alert.CallbackLossTimestamp);

                        LARGE_INTEGER now;
                        KeQuerySystemTime(&now);
                        LONGLONG lossLatencyMs = (now.QuadPart - g_State.Alert.ActivationTime.QuadPart) / 10000;

                        DbgPrint("[CanaryMesh%lu] SIGNAL A: CALLBACK POINTER REMOVED\n", (ULONG)CANARY_ID);
                        DbgPrint("[CanaryMesh%lu]   Process=%u Image=%u Thread=%u LatencyMs=%lld\n",
                            (ULONG)CANARY_ID, (ULONG)processCallbackPresent,
                            (ULONG)imageCallbackPresent, (ULONG)threadCallbackPresent, lossLatencyMs);

                        InterlockedOr(&g_State.Alert.DetectedSignals, ALERT_CALLBACK_POINTER_REMOVED);
                        CanaryCastVote(ALERT_CALLBACK_POINTER_REMOVED);
                    }
                }
            }

            // Signal B is behavioral: callback counters stop changing while activity is expected.
            if (!g_State.Alert.LivenessDropDetected) {
                if (CanaryIsLivenessCounterFrozen()) {
                    InterlockedExchange(&g_State.Alert.LivenessDropDetected, 1);

                    LARGE_INTEGER now;
                    KeQuerySystemTime(&now);
                    LONGLONG frozenLatencyMs = (now.QuadPart - g_State.Alert.ActivationTime.QuadPart) / 10000;

                    DbgPrint("[CanaryMesh%lu] SIGNAL B: CALLBACK LIVENESS FROZEN LatencyMs=%lld\n",
                        (ULONG)CANARY_ID, frozenLatencyMs);

                    // Callback loss while the suspect driver remains loaded is the strongest tamper pattern.
                    BOOLEAN driverStillThere = CanaryIsSuspectDriverLoaded(g_State.Alert.DriverName);

                    if (driverStillThere) {
                        DbgPrint("[CanaryMesh%lu] SIGNAL B+: PERSISTENT ATTACK — driver loaded + callbacks dead\n",
                            (ULONG)CANARY_ID);
                        InterlockedOr(&g_State.Alert.DetectedSignals, ALERT_DRIVER_LOADED_CALLBACKS_DEAD);
                        CanaryCastVote(ALERT_DRIVER_LOADED_CALLBACKS_DEAD);
                    }
                    else {
                        InterlockedOr(&g_State.Alert.DetectedSignals, ALERT_CALLBACK_LIVENESS_FROZEN);
                        CanaryCastVote(ALERT_CALLBACK_LIVENESS_FROZEN);
                    }
                }
            }

            // Keep reporting consensus every 60 seconds while the incident remains active.
            CanaryMaybeEmitPeriodicConsensus(ALERT_DRIVER_LOADED_CALLBACKS_DEAD);

            KeDelayExecutionThread(KernelMode, FALSE, &interval);
        }

        KeClearEvent(&g_State.AlertEvent);
    }

    DbgPrint("[CanaryMesh%lu] Callback watch thread stopping\n", (ULONG)CANARY_ID);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// ============================================================
// Driver watch thread - Signal C.
// ============================================================

VOID CanaryDriverWatchThread(PVOID Context) {
    UNREFERENCED_PARAMETER(Context);

    DbgPrint("[CanaryMesh%lu] Driver watch thread started\n", (ULONG)CANARY_ID);

    LARGE_INTEGER pollInterval;
    pollInterval.QuadPart = -(LONGLONG)(CanaryMesh_DRIVER_POLL_INTERVAL_MS * 10000);

    while (!g_State.ShouldStop) {

        LARGE_INTEGER timeout;
        timeout.QuadPart = -(LONGLONG)(CanaryMesh_ALERT_WINDOW_MS * 10000);

        // Workers sleep until DetectorOne dispatches a suspect-driver alert.
        NTSTATUS waitStatus = KeWaitForSingleObject(
            &g_State.AlertEvent, Executive, KernelMode, FALSE, &timeout);

        if (g_State.ShouldStop) break;

        if (waitStatus == STATUS_TIMEOUT || !g_State.Alert.Active) {
            KeDelayExecutionThread(KernelMode, FALSE, &pollInterval);
            continue;
        }

        DbgPrint("[CanaryMesh%lu] Driver watch activated for %S\n",
            (ULONG)CANARY_ID, g_State.Alert.DriverName);

        while (!g_State.ShouldStop && g_State.Alert.Active) {

            // Signal C tracks whether the suspected BYOVD driver quickly unloads after tampering.
            BOOLEAN loaded = CanaryIsSuspectDriverLoaded(g_State.Alert.DriverName);

            if (g_State.Table && InterlockedCompareExchange(&g_State.Table->ShutdownPending, 1, 1) == 1) {
                DbgPrint("[CanaryMesh%lu] ShutdownPending detected — stopping driver watch thread\n", (ULONG)CANARY_ID);
                break;
            }

            if (!loaded && g_State.Alert.DriverStillLoaded && !g_State.Alert.UnloadDetected) {

                LARGE_INTEGER unloadTime;
                KeQuerySystemTime(&unloadTime);

                InterlockedExchange(&g_State.Alert.UnloadDetected, 1);
                InterlockedExchange(&g_State.Alert.DriverStillLoaded, 0);
                g_State.Alert.UnloadTimestamp = unloadTime;

                LONGLONG durationMs = (unloadTime.QuadPart - g_State.Alert.LoadTimestamp.QuadPart) / 10000;

                DbgPrint("[CanaryMesh%lu] SIGNAL C: Driver UNLOADED Driver=%S DurationMs=%lld\n",
                    (ULONG)CANARY_ID, g_State.Alert.DriverName, durationMs);

                if (durationMs < CanaryMesh_FAST_UNLOAD_THRESHOLD_MS) {
                    DbgPrint("[CanaryMesh%lu] SIGNAL C: FAST UNLOAD — classic BYOVD pattern\n", (ULONG)CANARY_ID);
                    InterlockedOr(&g_State.Alert.DetectedSignals, ALERT_DRIVER_UNLOADED_FAST);
                    CanaryCastVote(ALERT_DRIVER_UNLOADED_FAST);
                }
                else {
                    DbgPrint("[CanaryMesh%lu] SIGNAL C: Slow unload DurationMs=%lld — correlate with A/B\n",
                        (ULONG)CANARY_ID, durationMs);
                }

                InterlockedExchange(&g_State.Alert.Active, 0);
                break;
            }

            KeDelayExecutionThread(KernelMode, FALSE, &pollInterval);
        }
    }

    DbgPrint("[CanaryMesh%lu] Driver watch thread stopping\n", (ULONG)CANARY_ID);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// ============================================================
// Peer heartbeat thread.
// ============================================================

VOID CanaryHeartbeatThread(PVOID Context) {
    UNREFERENCED_PARAMETER(Context);

    PCanaryMesh_CANARY_TABLE table = g_State.Table;
    if (!table || !MmIsAddressValid(table)) {
        PsTerminateSystemThread(STATUS_INVALID_ADDRESS);
        return;
    }

    PCANARY_IDENTITY mySlot = &table->Canaries[g_State.CanaryId - 1];

    LARGE_INTEGER interval;
    interval.QuadPart = -(LONGLONG)(CanaryMesh_HEARTBEAT_INTERVAL_MS * 10000);

    while (!g_State.ShouldStop) {

        if (g_State.Table && InterlockedCompareExchange(&g_State.Table->ShutdownPending, 1, 1) == 1) {
            DbgPrint("[CanaryMesh%lu] ShutdownPending detected — stopping heartbeat thread\n", (ULONG)CANARY_ID);
            break;
        }

        // Publish this canary heartbeat into the shared mesh table.
        if (MmIsAddressValid(mySlot) && MmIsAddressValid((PVOID)&mySlot->LastHeartbeatTime)) {
            InterlockedExchange64(&mySlot->LastHeartbeatTime, (LONG64)KeQueryInterruptTime());
            InterlockedIncrement(&mySlot->HeartbeatSequence);
            InterlockedExchange(&mySlot->Status, CANARY_STATUS_ALIVE);
        }

        ULONG aliveCount = 1;
        ULONG bound = (table->ExpectedCount > 0 && table->ExpectedCount <= CanaryMesh_MAX_CANARIES)
            ? table->ExpectedCount
            : CanaryMesh_MAX_CANARIES;

        // Check peer heartbeats so the mesh can detect quorum degradation.
        for (ULONG i = 0; i < bound; i++) {
            if (i == g_State.CanaryId - 1) continue;

            PCANARY_IDENTITY peer = &table->Canaries[i];

            if (!peer || !MmIsAddressValid(peer)) continue;

            volatile LONG64* pPeerHeartbeat = &peer->LastHeartbeatTime;
            if (!MmIsAddressValid((PVOID)pPeerHeartbeat)) continue;

            if (peer->CanaryId == 0) continue;

            LONG64 peerLastHeartbeat = *pPeerHeartbeat;
            LONG64 elapsed = (LONG64)KeQueryInterruptTime() - peerLastHeartbeat;
            LONGLONG elapsedMs = elapsed / 10000;

            if (elapsedMs < CanaryMesh_HEARTBEAT_TIMEOUT_MS) {
                aliveCount++;
                InterlockedExchange(&peer->Status, CANARY_STATUS_ALIVE);
            }
            else if (elapsedMs < CanaryMesh_HEARTBEAT_TIMEOUT_MS * 2) {
                InterlockedExchange(&peer->Status, CANARY_STATUS_SUSPECTED);
            }
            else {
                if (peer->Status != CANARY_STATUS_DEAD) {
                    InterlockedExchange(&peer->Status, CANARY_STATUS_DEAD);
                    DbgPrint("[CanaryMesh%lu] Peer Canary%lu DEAD ElapsedMs=%lld\n",
                        (ULONG)CANARY_ID, i + 1, elapsedMs);
                    if (g_State.Alert.Active)
                        CanaryCastVote(ALERT_CANARY_PEER_DEAD);
                }
            }
        }

        if (MmIsAddressValid(table)) {
            InterlockedExchange(&table->AliveCount, (LONG)aliveCount);

            if (aliveCount < table->QuorumRequired) {
                if (!table->HandoffComplete) {
                    KeDelayExecutionThread(KernelMode, FALSE, &interval);
                    continue;
                }
                DbgPrint("[CanaryMesh%lu] QUORUM DEGRADED Alive=%lu Required=%lu\n",
                    (ULONG)CANARY_ID, aliveCount, table->QuorumRequired);
                if (g_State.Alert.Active)
                    CanaryCastVote(ALERT_QUORUM_LOST);
            }
        }

        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

// ============================================================
// CanaryIsSuspectDriverLoaded
// ============================================================

// DetectorOne owns the authoritative driver-loaded flag; canaries only read it defensively.
BOOLEAN CanaryIsSuspectDriverLoaded(IN PWSTR DriverBaseName) {
    UNREFERENCED_PARAMETER(DriverBaseName);

    if (!g_State.Table || !MmIsAddressValid((PVOID)g_State.Table)) {
        return FALSE;
    }

    volatile LONG* pFlag = &g_State.Table->SuspectDriverStillLoaded;
    if (!MmIsAddressValid((PVOID)pFlag)) {
        return FALSE;
    }

    return (InterlockedCompareExchange(pFlag, 0, 0) == 1);
}


// ============================================================
// CanaryIsLivenessCounterFrozen — Signal B
// ============================================================

// Compare callback event counters against the alert-time baseline.
BOOLEAN CanaryIsLivenessCounterFrozen() {
    PCanaryMesh_EDR_CALLBACK_BASELINE baseline = &g_State.Table->CallbackBaseline;

    if (!baseline || !baseline->Valid) return FALSE;

    volatile LONG64* pProcessCounter = (volatile LONG64*)baseline->ProcessEventCounter;
    volatile LONG64* pImageCounter = (volatile LONG64*)baseline->ImageEventCounter;

    if (!pProcessCounter || !pImageCounter) return FALSE;

    if (!MmIsAddressValid((PVOID)pProcessCounter) || !MmIsAddressValid((PVOID)pImageCounter)) {
        DbgPrint("[CanaryMesh%lu] WARNING: Event counter pages are invalid!\n", (ULONG)CANARY_ID);
        return FALSE;
    }

    LONG64 currentProcess = InterlockedCompareExchange64(pProcessCounter, 0, 0);
    LONG64 currentImage = InterlockedCompareExchange64(pImageCounter, 0, 0);

    LONG64 deltaProcess = currentProcess - g_State.LivenessProcessBaseline;
    LONG64 deltaImage = currentImage - g_State.LivenessImageBaseline;

    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    LONGLONG elapsedMs = (now.QuadPart - g_State.LivenessBaselineCaptureTime.QuadPart) / 10000;

    if (deltaProcess > 0 || deltaImage > 0) {
        g_State.LivenessObservedAfterAlert = TRUE;
        g_State.LivenessProcessBaseline = currentProcess;
        g_State.LivenessImageBaseline = currentImage;
        KeQuerySystemTime(&g_State.LivenessBaselineCaptureTime);
    }

    if (elapsedMs >= CanaryMesh_LIVENESS_WINDOW_MS &&
        g_State.LivenessObservedAfterAlert &&
        deltaProcess == 0 && deltaImage == 0) {
        DbgPrint("[CanaryMesh%lu] Liveness FROZEN ElapsedMs=%lld ProcessDelta=%lld ImageDelta=%lld\n",
            (ULONG)CANARY_ID, elapsedMs, deltaProcess, deltaImage);
        return TRUE;
    }

    DbgPrint("[CanaryMesh%lu] Liveness OK ElapsedMs=%lld ProcessDelta=%lld ImageDelta=%lld\n",
        (ULONG)CANARY_ID, elapsedMs, deltaProcess, deltaImage);

    return FALSE;
}

