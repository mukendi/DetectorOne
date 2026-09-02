#include "header.h"

VOID DetectorOneQueueTelemetryEvent(
    IN DETECTORONE_EVENT_TYPE Type,
    IN ULONG64 ProcessId,
    IN ULONG64 ParentProcessId,
    IN ULONG64 ThreadId,
    IN PCUNICODE_STRING ImagePath,
    IN PCWSTR Detail,
    IN ULONG RiskScore,
    IN ULONG Flags)
{
    DetectorOneQueueTelemetryEventEx(Type, ProcessId, ParentProcessId,
        ThreadId, 0, 0, 0, ImagePath, Detail, RiskScore, Flags);
}

VOID DetectorOneQueueTelemetryEventEx(
    IN DETECTORONE_EVENT_TYPE Type,
    IN ULONG64 ProcessId,
    IN ULONG64 ParentProcessId,
    IN ULONG64 ThreadId,
    IN ULONG64 Address,
    IN ULONG64 RegionSize,
    IN ULONG Protection,
    IN PCUNICODE_STRING ImagePath,
    IN PCWSTR Detail,
    IN ULONG RiskScore,
    IN ULONG Flags)
{
    if (g_Unloading) return;

    DETECTORONE_TELEMETRY_EVENT event = { 0 };
    event.Size = sizeof(DETECTORONE_TELEMETRY_EVENT);
    event.Type = (ULONG)Type;
    event.Sequence = (ULONG64)InterlockedIncrement64(&g_TelemetrySequence);
    KeQuerySystemTime(&event.Timestamp);
    event.ProcessId = ProcessId;
    event.ParentProcessId = ParentProcessId;
    event.ThreadId = ThreadId;
    event.Address = Address;
    event.RegionSize = RegionSize;
    event.Protection = Protection;
    event.RiskScore = RiskScore;
    event.Flags = Flags;

    if (ImagePath && ImagePath->Buffer && ImagePath->Length > 0) {
        SIZE_T chars = min((SIZE_T)(ImagePath->Length / sizeof(WCHAR)),
            (SIZE_T)(DETECTORONE_EVENT_TEXT_MAX - 1));
        RtlCopyMemory(event.ImagePath, ImagePath->Buffer, chars * sizeof(WCHAR));
        event.ImagePath[chars] = L'\0';
    }

    if (Detail) {
        RtlStringCchCopyW(event.Detail, ARRAYSIZE(event.Detail), Detail);
    }

    ExAcquireFastMutex(&g_TelemetryLock);

    ULONG index = (g_TelemetryHead + g_TelemetryCount) % DETECTORONE_EVENT_RING_SIZE;
    if (g_TelemetryCount == DETECTORONE_EVENT_RING_SIZE) {
        g_TelemetryHead = (g_TelemetryHead + 1) % DETECTORONE_EVENT_RING_SIZE;
        index = (g_TelemetryHead + g_TelemetryCount - 1) % DETECTORONE_EVENT_RING_SIZE;
        g_TelemetryDropped++;
    }
    else {
        g_TelemetryCount++;
    }

    g_TelemetryRing[index] = event;
    ExReleaseFastMutex(&g_TelemetryLock);
}

ULONG DetectorOneDrainTelemetryEvents(
    OUT PDETECTORONE_EVENT_BATCH Batch,
    IN ULONG OutputLength)
{
    if (!Batch || OutputLength < sizeof(DETECTORONE_EVENT_BATCH)) {
        return 0;
    }

    RtlZeroMemory(Batch, sizeof(DETECTORONE_EVENT_BATCH));
    Batch->Version = 1;

    ExAcquireFastMutex(&g_TelemetryLock);

    ULONG toCopy = min(g_TelemetryCount, (ULONG)DETECTORONE_MAX_EVENTS_PER_BATCH);
    for (ULONG i = 0; i < toCopy; i++) {
        Batch->Events[i] = g_TelemetryRing[g_TelemetryHead];
        g_TelemetryHead = (g_TelemetryHead + 1) % DETECTORONE_EVENT_RING_SIZE;
        g_TelemetryCount--;
    }

    Batch->Count = toCopy;
    Batch->DroppedEvents = g_TelemetryDropped;
    g_TelemetryDropped = 0;

    ExReleaseFastMutex(&g_TelemetryLock);
    return sizeof(DETECTORONE_EVENT_BATCH);
}
