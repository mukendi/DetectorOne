#include "CanaryMesh.h"

// ============================================================
// Peer consensus and alert emission.
// ============================================================

VOID CanaryMaybeEmitPeriodicConsensus(IN CanaryMesh_ALERT_TYPE AlertType) {
    if (!g_State.Alert.Active) return;

    LARGE_INTEGER now;
    KeQuerySystemTime(&now);

    LONGLONG elapsedMs = 0;
    // Throttle repeated reports so an active tamper incident is refreshed once per interval.
    if (g_State.LastConsensusReportTime.QuadPart != 0) {
        elapsedMs = (now.QuadPart - g_State.LastConsensusReportTime.QuadPart) / 10000;
    }

    // Throttle repeated reports so an active tamper incident is refreshed once per interval.
    if (g_State.LastConsensusReportTime.QuadPart == 0 ||
        elapsedMs >= CanaryMesh_CONSENSUS_REPORT_INTERVAL_MS) {

        g_State.LastConsensusReportTime = now;

        if (g_State.Table) {
            LONG votes = InterlockedCompareExchange(&g_State.Table->AlertVotes, 0, 0);
            if ((ULONG)votes >= g_State.Table->QuorumRequired) {
                DbgPrint("[CanaryMesh%lu] Periodic consensus refresh for AlertType=%lu (Votes=%ld)\n",
                    (ULONG)CANARY_ID, (ULONG)AlertType, votes);
                CanaryEmitConsensusAlert(AlertType, votes);
            }
        }
    }
}

VOID CanaryCastVote(IN CanaryMesh_ALERT_TYPE AlertType) {
    PCanaryMesh_CANARY_TABLE table = g_State.Table;
    if (!table) return;

    // Each canary owns one bit in the shared vote bitmap.
    LONG voteBit = (LONG)(1UL << (g_State.CanaryId - 1));
    LONG oldBitmap;
    LONG newBitmap;

    // Atomically publish the vote without allowing duplicate votes from the same canary.
    do {
        oldBitmap = InterlockedCompareExchange(&table->AlertVoteBitmap, 0, 0);
        if (oldBitmap & voteBit) {
            DbgPrint("[CanaryMesh%lu] Vote already recorded AlertType=%lu Bitmap=0x%X\n",
                (ULONG)CANARY_ID, (ULONG)AlertType, oldBitmap);
            return;
        }
        newBitmap = oldBitmap | voteBit;
    } while (InterlockedCompareExchange(&table->AlertVoteBitmap, newBitmap, oldBitmap) != oldBitmap);

    LONG votes = InterlockedIncrement(&table->AlertVotes);

    DbgPrint("[CanaryMesh%lu] Vote AlertType=%lu Votes=%ld/%lu Bitmap=0x%X Generation=%ld\n",
        (ULONG)CANARY_ID, (ULONG)AlertType, votes, table->QuorumRequired, newBitmap, table->AlertGeneration);

    // The first canary that observes quorum emits the collegial alert for this generation.
    if ((ULONG)votes >= table->QuorumRequired) {
        LONG previous = InterlockedCompareExchange(&table->ConsensusEmitted, 1, 0);
        if (previous == 0)
            CanaryEmitConsensusAlert(AlertType, votes);
    }
}

VOID CanaryEmitConsensusAlert(
    IN CanaryMesh_ALERT_TYPE AlertType,
    IN LONG Votes
) {
    PCanaryMesh_CANARY_TABLE table = g_State.Table;

    // Compute investigation timings from the local incident context.
    LONGLONG loadToUnloadMs = 0;
    if (g_State.Alert.UnloadDetected) {
        loadToUnloadMs = (g_State.Alert.UnloadTimestamp.QuadPart - g_State.Alert.LoadTimestamp.QuadPart) / 10000;
    }

    LONGLONG callbackLossMs = 0;
    if (g_State.Alert.CallbackRemovalDetected) {
        callbackLossMs = (g_State.Alert.CallbackLossTimestamp.QuadPart - g_State.Alert.LoadTimestamp.QuadPart) / 10000;
    }

    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    LONGLONG detectLatencyMs = (now.QuadPart - g_State.Alert.ActivationTime.QuadPart) / 10000;

    // Mark the shared alert as consumed; periodic refreshes still use the local active incident state.
    if (table) {
        InterlockedExchange(&table->AlertActive, 0);
    }

    DbgPrint("\n");
    DbgPrint("[CanaryMesh CONSENSUS] ===================================\n");
    DbgPrint("[CanaryMesh CONSENSUS] *** COLLEGIAL ALERT ***\n");
    DbgPrint("[CanaryMesh CONSENSUS] AlertType       = %lu\n", (ULONG)AlertType);
    DbgPrint("[CanaryMesh CONSENSUS] DetectedSignals = 0x%08X\n", (ULONG)g_State.Alert.DetectedSignals);
    DbgPrint("[CanaryMesh CONSENSUS] Votes           = %ld/%lu\n", Votes, table ? table->QuorumRequired : 0);
    DbgPrint("[CanaryMesh CONSENSUS] Driver          = %S\n", g_State.Alert.DriverName);
    DbgPrint("[CanaryMesh CONSENSUS] RiskScore       = %lu\n", g_State.Alert.RiskScore);
    DbgPrint("[CanaryMesh CONSENSUS] Signal A        = %u (callback pointer)\n", (ULONG)g_State.Alert.CallbackRemovalDetected);
    DbgPrint("[CanaryMesh CONSENSUS] Signal B        = %u (liveness frozen)\n", (ULONG)g_State.Alert.LivenessDropDetected);
    DbgPrint("[CanaryMesh CONSENSUS] Signal C        = %u (driver unloaded)\n", (ULONG)g_State.Alert.UnloadDetected);
    DbgPrint("[CanaryMesh CONSENSUS] CallbackLossMs  = %lld\n", callbackLossMs);
    DbgPrint("[CanaryMesh CONSENSUS] DriverDurationMs= %lld\n", loadToUnloadMs);
    DbgPrint("[CanaryMesh CONSENSUS] DetectLatencyMs = %lld\n", detectLatencyMs);
    DbgPrint("[CanaryMesh CONSENSUS] ActiveCanaries  = %ld\n", table ? table->AliveCount : 0);
    DbgPrint("[CanaryMesh CONSENSUS] ===================================\n");
    DbgPrint("\n");
}

// ============================================================
// Utilities.
// ============================================================

VOID CanaryLogState(IN PCSTR Context) {
    PCanaryMesh_CANARY_TABLE table = g_State.Table;
    if (!table) return;

    DbgPrint("[CanaryMesh%lu] State [%s] Registered=%ld Alive=%ld/%lu Quorum=%lu Handoff=%ld\n",
        (ULONG)CANARY_ID, Context,
        table->RegisteredCount,
        table->AliveCount,
        table->ExpectedCount,
        table->QuorumRequired,
        table->HandoffComplete);
}
