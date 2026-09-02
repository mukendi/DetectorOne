#include "header.h"

// DetectorOne kernel notification callbacks and device dispatch helpers.

#define DetectorOneThreadQuerySetWin32StartAddress ((THREADINFOCLASS)9)

static BOOLEAN DetectorOneIsExecuteReadWriteProtect(ULONG Protect)
{
    ULONG normalizedProtect = Protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
    return normalizedProtect == PAGE_EXECUTE_READWRITE;
}

static BOOLEAN DetectorOneQueryThreadStartMemory(
    HANDLE ProcessId,
    HANDLE ThreadId,
    PVOID* StartAddress,
    PMEMORY_BASIC_INFORMATION MemoryInfo)
{
    HANDLE hThread = NULL;
    HANDLE hProcess = NULL;
    CLIENT_ID cid = { 0 };
    OBJECT_ATTRIBUTES oa;

    if (!StartAddress || !MemoryInfo) return FALSE;

    *StartAddress = NULL;
    RtlZeroMemory(MemoryInfo, sizeof(*MemoryInfo));

    cid.UniqueProcess = ProcessId;
    cid.UniqueThread = ThreadId;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    if (!NT_SUCCESS(ZwOpenThread(
        &hThread, THREAD_QUERY_LIMITED_INFORMATION, &oa, &cid))) {
        return FALSE;
    }

    NTSTATUS status = ZwQueryInformationThread(
        hThread,
        DetectorOneThreadQuerySetWin32StartAddress,
        StartAddress,
        sizeof(*StartAddress),
        NULL);

    ZwClose(hThread);

    if (!NT_SUCCESS(status) || *StartAddress == NULL) return FALSE;

    cid.UniqueProcess = ProcessId;
    cid.UniqueThread = NULL;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    if (!NT_SUCCESS(ZwOpenProcess(
        &hProcess, PROCESS_QUERY_INFORMATION, &oa, &cid))) {
        return FALSE;
    }

    status = ZwQueryVirtualMemory(
        hProcess,
        *StartAddress,
        MemoryBasicInformation,
        MemoryInfo,
        sizeof(*MemoryInfo),
        NULL);

    ZwClose(hProcess);
    return NT_SUCCESS(status);
}

VOID DetectorOneLoadImageNotify(PUNICODE_STRING FullImageName,HANDLE  ProcessId,PIMAGE_INFO ImageInfo)
{
    if (g_Unloading) return;
    if (ImageInfo == NULL || ImageInfo->ImageBase == NULL) return;
    if (FullImageName == NULL || FullImageName->Buffer == NULL) return;

    // Increment the liveliness counter
    // Monitored by the canaries to detect if this callback
    // is still being invoked (Signal B on the canaries' side)
    //InterlockedIncrement64(&g_ImageEventCounter);

    if (ImageInfo->SystemModeImage &&
        DetectorOneIsSysDriverName(FullImageName) &&
        !DetectorOneIsDriverFromSystem32Drivers(FullImageName)) {
        InterlockedIncrement64(&g_ImageEventCounter);
        DbgPrint("[DetectorOne] ALERT: driver from non-standard path "
            "CurrentPid=%llu CurrentImage=%s Name=%wZ\n",
            (ULONG_PTR)PsGetCurrentProcessId(),
            (PCSTR)PsGetProcessImageFileName(PsGetCurrentProcess()),
            FullImageName);
    }

    // Only kernel-mode driver images are relevant for BYOVD IAT analysis.
    if (!ImageInfo->SystemModeImage ||
        !DetectorOneIsSysDriverName(FullImageName)) {
        return;
    }
    // Windows reports driver unload through the same image callback with
    // ImageSize == 0. Use that to stop canary persistence tracking.
    if (ImageInfo->ImageSize == 0) {
        if (g_CanaryTable && g_CanaryTable->SuspectDriverStillLoaded && g_CanaryTable->SuspectDriverTracked[0] != L'\0') {

            UNICODE_STRING tracked;
            RtlInitUnicodeString(
                &tracked, g_CanaryTable->SuspectDriverTracked);

            if (FullImageName &&
                RtlEqualUnicodeString(FullImageName, &tracked, TRUE)) {

                InterlockedExchange(
                    &g_CanaryTable->SuspectDriverStillLoaded, 0);

                DbgPrint("[DetectorOne] Suspect driver UNLOADED: %wZ\n",
                    FullImageName);
            }
        }
        return; // No IAT analysis is needed on unload notification
    }

    DETECTORONE_IAT_SCORE iatScore = { 0 };
    DETECTORONE_IAT_CAPABILITIES iatCaps = { 0 };
    ULONG totalRiskScore = 0;

    HANDLE currentPid = PsGetCurrentProcessId();
    PCSTR currentImageName = (PCSTR)PsGetProcessImageFileName(PsGetCurrentProcess());
    
    if (!currentImageName) currentImageName = "<unknown>";

    NTSTATUS status = DetectorOneAnalyzeDriverIAT(
        ImageInfo->ImageBase, ImageInfo->ImageSize,
        &iatScore, &totalRiskScore, &iatCaps);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[DetectorOne] IAT analysis failed "
            "Status=0x%08X Name=%wZ\n", status, FullImageName);
        return;
    }

    DbgPrint("[DetectorOne] Loaded NotifyPid=%llu CurrentPid=%llu "
        "CurrentImage=%s Base=%p Size=0x%X Risk=%lu Name=%wZ\n",
        (ULONG_PTR)ProcessId,
        (ULONG_PTR)currentPid,
        currentImageName,
        ImageInfo->ImageBase,
        ImageInfo->ImageSize,
        totalRiskScore,
        FullImageName);

    BYOVD_PRIMITIVE_CATEGORY category = KratosClassifyPrimitive(&iatScore, &iatCaps);
    DetectorOneQueueTelemetryEvent(DETECTORONE_EVENT_IMAGE_LOAD,
        (ULONG64)(ULONG_PTR)currentPid, 0, 0, FullImageName,
        L"kernel-image", totalRiskScore, (ULONG)category);

    // High-risk policy: process killer, physical memory access, arbitrary
    // section mapping, or a score above the configured threshold.
    BOOLEAN isHighRisk = iatScore.ImportsZwTerminateProcess ||
        iatScore.ImportsMmMapIoSpace ||
        (iatScore.ImportsMmGetPhysicalAddress &&
            iatScore.ImportsZwMapViewOfSection) ||
        totalRiskScore >= DetectorOne_HIGH_RISK_THRESHOLD;

    if (isHighRisk) {

        KratosHandleHighRiskDriver(FullImageName, &iatScore, &iatCaps, totalRiskScore);

        if (InterlockedCompareExchange(&g_AlertDispatching, 1, 0) == 0) {
            if (g_CanaryTable) {
                InterlockedIncrement(&g_CanaryTable->AlertGeneration);
                InterlockedExchange(&g_CanaryTable->AlertVotes, 0);
                InterlockedExchange(&g_CanaryTable->AlertVoteBitmap, 0);
                InterlockedExchange(&g_CanaryTable->AlertActive, 0);
                InterlockedExchange(&g_CanaryTable->ConsensusEmitted, 0);
                InterlockedExchange(&g_CanaryTable->AlertDispatched, 1);
                InterlockedExchange(&g_CanaryTable->SuspectDriverStillLoaded, 1);
                if (FullImageName && FullImageName->Buffer) {
                    RtlStringCchCopyW(
                        g_CanaryTable->SuspectDriverTracked,
                        ARRAYSIZE(g_CanaryTable->SuspectDriverTracked),
                        FullImageName->Buffer
                    );
                }
            }

            LARGE_INTEGER loadTime;
            KeQuerySystemTime(&loadTime);


            DbgPrint("[DetectorOne] ALERT: suspicious driver "
                "CurrentPid=%llu CurrentImage=%s "
                "ZwTerminateProcess=%u MmMapIoSpace=%u "
                "MmGetPhysicalAddress=%u ZwMapViewOfSection=%u "
                "Risk=%lu Name=%wZ\n",
                (ULONG_PTR)currentPid, currentImageName,
                (ULONG)iatScore.ImportsZwTerminateProcess,
                (ULONG)iatScore.ImportsMmMapIoSpace,
                (ULONG)iatScore.ImportsMmGetPhysicalAddress,
                (ULONG)iatScore.ImportsZwMapViewOfSection,
                totalRiskScore, FullImageName);

            DetectorOneDispatchAlertToCanaries(
                FullImageName, &loadTime, totalRiskScore);

            InterlockedExchange(&g_AlertDispatching, 0);

        }
      
    }
}

// Process callback. Besides local inventory, this increments the liveness
// counter that canaries use to detect callback freezing/removal.
VOID DetectorOneCreateProcessNotify(
    PEPROCESS Process, HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    if (g_Unloading) return;

    InterlockedIncrement64(&g_ProcessEventCounter);

    if (CreateInfo != NULL) {
        PPROCESS_ENTRY newProcess =
            (PPROCESS_ENTRY)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, sizeof(PROCESS_ENTRY), POOL_TAG);
        if (!newProcess) return;

        RtlZeroMemory(newProcess, sizeof(*newProcess));
        newProcess->ProcessId = ProcessId;
        newProcess->ParentProcessId = CreateInfo->ParentProcessId;
        KeQuerySystemTime(&newProcess->CreateTime);

        if (CreateInfo->ImageFileName &&
            CreateInfo->ImageFileName->Length > 0) {
            USHORT lengthBytes = CreateInfo->ImageFileName->Length;
            SIZE_T sizeAlloc = (SIZE_T)lengthBytes + sizeof(WCHAR);
            PWCHAR buffer = (PWCHAR)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, sizeAlloc, 'FgmI');
            if (buffer) {
                RtlCopyMemory(buffer,
                    CreateInfo->ImageFileName->Buffer, lengthBytes);
                buffer[lengthBytes / sizeof(WCHAR)] = L'\0';
                newProcess->ImageFileName.Length = lengthBytes;
                newProcess->ImageFileName.MaximumLength = (USHORT)sizeAlloc;
                newProcess->ImageFileName.Buffer = buffer;
            }
        }

        ExAcquireFastMutex(&g_ProcessListLock);
        InsertTailList(&g_ProcessList, &newProcess->ProcessListEntry);
        ExReleaseFastMutex(&g_ProcessListLock);

        if (newProcess->ImageFileName.Buffer) {
            DetectorOneQueueTelemetryEvent(DETECTORONE_EVENT_PROCESS_CREATE,
                (ULONG64)(ULONG_PTR)newProcess->ProcessId,
                (ULONG64)(ULONG_PTR)newProcess->ParentProcessId,
                0, &newProcess->ImageFileName, L"create", 0, 0);
            DbgPrint("[DetectorOne] Created PID=%llu Parent=%llu "
                "Image=%wZ\n",
                (ULONG_PTR)newProcess->ProcessId,
                (ULONG_PTR)newProcess->ParentProcessId,
                &newProcess->ImageFileName);
        }
    }
    else {
        ExAcquireFastMutex(&g_ProcessListLock);
        PLIST_ENTRY entry = g_ProcessList.Flink;
        BOOLEAN found = FALSE;

        while (entry != &g_ProcessList) {
            PPROCESS_ENTRY pEntry =
                CONTAINING_RECORD(entry, PROCESS_ENTRY, ProcessListEntry);
            if (pEntry->ProcessId == ProcessId) {
                RemoveEntryList(&pEntry->ProcessListEntry);
                if (pEntry->ImageFileName.Buffer) {
                    ExFreePoolWithTag(pEntry->ImageFileName.Buffer, 'FgmI');
                    pEntry->ImageFileName.Buffer = NULL;
                }
                ExFreePoolWithTag(pEntry, POOL_TAG);
                found = TRUE;
                break;
            }
            entry = entry->Flink;
        }

        ExReleaseFastMutex(&g_ProcessListLock);
        DetectorOneQueueTelemetryEvent(DETECTORONE_EVENT_PROCESS_EXIT,
            (ULONG64)(ULONG_PTR)ProcessId, 0, 0, NULL, L"exit", 0, 0);
        if (!found) {
            DbgPrint("[DetectorOne] Exit for unknown PID=%llu\n",
                (ULONG_PTR)ProcessId);
        }
    }
}

// Thread callback. Tracks thread activity and contributes to the EDR telemetry
// stream used to reason about process behavior around suspicious drivers.
VOID DetectorOneCreateThreadNotify(
    HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
    if (g_Unloading) return;

    HANDLE hProcess = NULL;
    CLIENT_ID cid = { 0 };
    OBJECT_ATTRIBUTES oa;

    if (Create) {
        PTHREAD_ENTRY newThread =
            (PTHREAD_ENTRY)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, sizeof(THREAD_ENTRY), POOL_TAG);
        if (!newThread) return;

        RtlZeroMemory(newThread, sizeof(*newThread));
        newThread->ProcessId = ProcessId;
        newThread->ThreadId = ThreadId;
        KeQuerySystemTime(&newThread->CreateTime);

        ExAcquireFastMutex(&g_ThreadListLock);
#if DETECTORONE_STREAM_THREAD_EVENTS
        DetectorOneQueueTelemetryEvent(DETECTORONE_EVENT_THREAD_CREATE,
            (ULONG64)(ULONG_PTR)ProcessId, 0,
            (ULONG64)(ULONG_PTR)ThreadId, NULL, L"create", 0, 0);
#endif
        InsertTailList(&g_ThreadList, &newThread->ThreadListEntry);
        ExReleaseFastMutex(&g_ThreadListLock);

        // High-signal thread telemetry: a new thread whose start address lands
        // in RWX committed memory is worth streaming even when raw thread
        // telemetry is disabled to avoid flooding DetectorOneEngine.
        PVOID startAddress = NULL;
        MEMORY_BASIC_INFORMATION startMemory = { 0 };
        if (DetectorOneQueryThreadStartMemory(
            ProcessId, ThreadId, &startAddress, &startMemory) &&
            startMemory.State == MEM_COMMIT &&
            DetectorOneIsExecuteReadWriteProtect(startMemory.Protect)) {

            DbgPrint("[DetectorOne] ALERT: thread start in RWX memory "
                "PID=%llu TID=%llu Start=%p Region=%p Size=0x%Ix Protect=0x%X\n",
                (ULONG_PTR)ProcessId,
                (ULONG_PTR)ThreadId,
                startAddress,
                startMemory.BaseAddress,
                startMemory.RegionSize,
                startMemory.Protect);

            DetectorOneQueueTelemetryEventEx(
                DETECTORONE_EVENT_RWX_THREAD_START,
                (ULONG64)(ULONG_PTR)ProcessId,
                0,
                (ULONG64)(ULONG_PTR)ThreadId,
                (ULONG64)(ULONG_PTR)startAddress,
                (ULONG64)startMemory.RegionSize,
                startMemory.Protect,
                NULL,
                L"thread-start-rwx",
                250,
                0);
        }

        cid.UniqueProcess = newThread->ProcessId;
        cid.UniqueThread = newThread->ThreadId;
        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

        if (NT_SUCCESS(ZwOpenProcess(
            &hProcess, PROCESS_QUERY_INFORMATION, &oa, &cid))) {
            MEMORY_BASIC_INFORMATION mbi = { 0 };
            UCHAR* address = NULL;

            while (NT_SUCCESS(ZwQueryVirtualMemory(hProcess, address,
                MemoryBasicInformation, &mbi, sizeof(mbi), NULL))) {
                // Use the current protection, not AllocationProtect. A region
                // may have been allocated as RWX and later split into RX/RW
                // pages; only the active PAGE_EXECUTE_READWRITE state should
                // be reported as RWX telemetry.
                if (mbi.State == MEM_COMMIT &&
                    DetectorOneIsExecuteReadWriteProtect(mbi.Protect)) {

                    RWX_REGION_ENTRY newEntry = { 0 };
                    newEntry.ProcessId = ProcessId;
                    newEntry.BaseAddress = mbi.BaseAddress;
                    newEntry.RegionSize = mbi.RegionSize;

                    PEPROCESS process = NULL;
                    if (NT_SUCCESS(PsLookupProcessByProcessId(
                        newEntry.ProcessId, &process))) {
                        DetectorOneCaptureRWXSnapshot(
                            process, mbi.BaseAddress, &newEntry);
                        ObDereferenceObject(process);
                    }

                    ExAcquireFastMutex(&g_RwxTableLock);
                    RtlInsertElementGenericTableAvl(
                        &g_RwxTable, &newEntry, sizeof(newEntry), NULL);
                    ExReleaseFastMutex(&g_RwxTableLock);

                    // Stream only the discovered RWX region metadata. The
                    // snapshot bytes stay kernel-local for future comparison.
                    DetectorOneQueueTelemetryEventEx(
                        DETECTORONE_EVENT_RWX_REGION,
                        (ULONG64)(ULONG_PTR)ProcessId,
                        0,
                        (ULONG64)(ULONG_PTR)ThreadId,
                        (ULONG64)(ULONG_PTR)mbi.BaseAddress,
                        (ULONG64)mbi.RegionSize,
                        mbi.Protect,
                        NULL,
                        L"rwx-region",
                        100,
                        0);
                }
                if (mbi.RegionSize == 0) break;
                address += mbi.RegionSize;
            }
            ZwClose(hProcess);
        }
    }
    else {
        ExAcquireFastMutex(&g_ThreadListLock);
        PLIST_ENTRY entry = g_ThreadList.Flink;
        BOOLEAN found = FALSE;

        while (entry != &g_ThreadList) {
            PTHREAD_ENTRY pEntry =
                CONTAINING_RECORD(entry, THREAD_ENTRY, ThreadListEntry);
            if (pEntry->ThreadId == ThreadId) {
                RemoveEntryList(&pEntry->ThreadListEntry);
                ExFreePool(pEntry);
                found = TRUE;
                break;
            }
            entry = entry->Flink;
        }
        ExReleaseFastMutex(&g_ThreadListLock);
#if DETECTORONE_STREAM_THREAD_EVENTS
        DetectorOneQueueTelemetryEvent(DETECTORONE_EVENT_THREAD_EXIT,
            (ULONG64)(ULONG_PTR)ProcessId, 0,
            (ULONG64)(ULONG_PTR)ThreadId, NULL, L"exit", 0, 0);
#endif
    }
}

// RWX Snapshot

VOID DetectorOneCaptureRWXSnapshot(
    PEPROCESS Process, PVOID RemoteAddress, PRWX_REGION_ENTRY Entry)
{
    SIZE_T bytesRead = 0;
    NTSTATUS status = MmCopyVirtualMemory(
        Process, RemoteAddress,
        PsGetCurrentProcess(), Entry->ContentSnapShot,
        SNAPSHOT_SIZE, KernelMode, &bytesRead);

    Entry->SnapshotActualSize = NT_SUCCESS(status) ? bytesRead : 0;
}

// Registry pre-load enforcement path. Driver services normally write ImagePath
// before NtLoadDriver loads the .sys. Returning an error here blocks that
// registry write and stops the load chain early.
NTSTATUS DetectorOneRegistryCallback(
    PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    if (g_Unloading) return STATUS_SUCCESS;

    REG_NOTIFY_CLASS operation =
        (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    if (operation == RegNtPreSetValueKey) {
        PREG_SET_VALUE_KEY_INFORMATION setInfo =
            (PREG_SET_VALUE_KEY_INFORMATION)Argument2;

        if (!setInfo || !setInfo->Object || !setInfo->ValueName)
            return STATUS_SUCCESS;
        // Only ImagePath matters for pre-load driver enforcement.
        if (!DetectorOneUnicodeEqualsInsensitive(
            setInfo->ValueName, L"ImagePath"))
            goto LogOtherValues;
        // Restrict the policy to driver service keys.
        PCUNICODE_STRING keyName = NULL;
        BOOLEAN releaseKey = FALSE;

        NTSTATUS s = CmCallbackGetKeyObjectIDEx(
            &g_RegistryCallbackCookie,
            setInfo->Object, NULL, &keyName, 0);

        if (!NT_SUCCESS(s) || !keyName) return STATUS_SUCCESS;
        releaseKey = TRUE;

        if (!DetectorOneUnicodeContainsInsensitive(
            keyName, L"\\Services\\"))
            goto Cleanup;
        // Extract the ImagePath value written by the service installer/loader.
        if (!setInfo->Data || setInfo->DataSize < sizeof(WCHAR))
            goto Cleanup;

        if (setInfo->Type != REG_SZ &&
            setInfo->Type != REG_EXPAND_SZ)
            goto Cleanup;

        PWSTR imagePathValue = (PWSTR)setInfo->Data;

        DbgPrint("[DetectorOne] Pre-load check: Key=%wZ "
            "ImagePath=%S\n", keyName, imagePathValue);
        // Analyze the driver file before it is loaded, while this registry write
        // can still be denied safely.
        DETECTORONE_IAT_SCORE iatScore;
        DETECTORONE_IAT_CAPABILITIES iatCaps;

        RtlZeroMemory(&iatScore, sizeof(iatScore));
        RtlZeroMemory(&iatCaps, sizeof(iatCaps));

        ULONG riskScore = 0;

        NTSTATUS analysisStatus = KratosReadAndAnalyzeDriverOnDisk(
            imagePathValue, &riskScore, &iatScore, &iatCaps);

        if (!NT_SUCCESS(analysisStatus)) {
            // Do not block a driver only because pre-load disk analysis could
            // not classify it. Some simple or lab-built drivers may not parse
            // cleanly through the on-disk IAT path even though they expose no
            // dangerous imports. Blocking stays tied to positive risk signals.
            DbgPrint("[DetectorOne] Pre-load IAT analysis incomplete: "
                "Status=0x%08X ImagePath=%S Risk=%lu\n",
                analysisStatus, imagePathValue, riskScore);
        }
        // Blocking decision for pre-load enforcement.
        BYOVD_PRIMITIVE_CATEGORY category = KratosClassifyPrimitive(&iatScore, &iatCaps);

        BOOLEAN shouldBlock = FALSE;
        PCSTR   blockReason = NULL;
        // Block pure process-killer drivers immediately.
        if (category == PRIMITIVE_DRIVER_KILLER) {
            shouldBlock = TRUE;
            blockReason = "ZwTerminateProcess without physical memory primitive";
        }

        if (shouldBlock) {
            DbgPrint("[DetectorOne] *** BLOCKING DRIVER LOAD ***\n");
            DbgPrint("[DetectorOne]   Driver   : %S\n", imagePathValue);
            DbgPrint("[DetectorOne]   Reason   : %s\n", blockReason);
            DbgPrint("[DetectorOne]   Risk     : %lu\n", riskScore);
            DbgPrint("[DetectorOne]   Category : %lu\n",
                (ULONG)category);
            DbgPrint("[DetectorOne]   ZwTerminateProcess : %u\n",
                (ULONG)iatScore.ImportsZwTerminateProcess);
            DbgPrint("[DetectorOne]   MmMapIoSpace       : %u\n",
                (ULONG)iatScore.ImportsMmMapIoSpace);
            // Keep the denied service entry for later correlation and logs.
            KratosStoreServiceEntry(keyName, imagePathValue, TRUE);
            UNICODE_STRING blockedImagePath;
            RtlInitUnicodeString(&blockedImagePath, imagePathValue);
            DetectorOneQueueTelemetryEvent(DETECTORONE_EVENT_DRIVER_BLOCKED,
                (ULONG64)(ULONG_PTR)PsGetCurrentProcessId(), 0, 0,
                &blockedImagePath, L"blocked", riskScore, (ULONG)category);
            // Release the registry key name before denying the write.
            if (releaseKey) CmCallbackReleaseKeyObjectIDEx(keyName);
            // Deny the ImagePath write. NtLoadDriver will not have a valid
            // service image path to load.
            return STATUS_ACCESS_DENIED;
        }
        // Accepted driver path: remember service metadata in case later unload
        // or correlation is needed.
        KratosStoreServiceEntry(keyName, imagePathValue, FALSE);

        DetectorOneLogRegistryServiceEvent(
            "set-value", keyName, setInfo->ValueName,
            setInfo->Type, setInfo->DataSize);

    Cleanup:
        if (releaseKey) CmCallbackReleaseKeyObjectIDEx(keyName);
        return STATUS_SUCCESS;
    }

LogOtherValues:
    // Other service values are logged but not blocked by this policy path.

    return STATUS_SUCCESS;
}

NTSTATUS DetectorOneTestSignalA()
{
    if (!g_ProcessCallbackRegistered) {
        DbgPrint("[DetectorOne] TEST: Process callback already removed\n");
        return STATUS_ALREADY_DISCONNECTED;
    }

    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(
        DetectorOneCreateProcessNotify,
        TRUE);

    if (NT_SUCCESS(status)) {
        g_ProcessCallbackRegistered = FALSE;
        DbgPrint("[DetectorOne] TEST: Process callback self-removed\n");
    }
    else {
        DbgPrint("[DetectorOne] TEST: Process callback self-remove failed Status=0x%08X\n",
            status);
    }

    return status;
}
// Device-control dispatch path used primarily by canaries for registration and
// controlled test signals.
NTSTATUS DetectorOneDispatchIoctl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR bytesReturned = 0;

    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (controlCode) {
    
    case IOCTL_KRATOS_REGISTER:
    {
        if (inputLen < sizeof(KRATOS_REGISTER_REQUEST) ||
            outputLen < sizeof(KRATOS_REGISTER_RESPONSE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        // Copy the request before modifying the METHOD_BUFFERED system buffer.
        KRATOS_REGISTER_REQUEST reqCopy;
        RtlCopyMemory(&reqCopy, buffer, sizeof(KRATOS_REGISTER_REQUEST));

        // Clear the full response-sized buffer before writing the response.
        // Without this clear, stale request bytes may be interpreted as
        // response fields such as AlertEntryPoint at offset 16.
        // par le canari comme ProcessCallbackAddress
        RtlZeroMemory(buffer, sizeof(KRATOS_REGISTER_RESPONSE));

        // Enregistrer le canari
        NTSTATUS regStatus = DetectorOneRegisterCanary(
            reqCopy.CanaryId,
            reqCopy.DriverObjectAddress,
            reqCopy.AlertEntryPoint
        );

        // Fill every response field consumed by CanaryMesh.
        PKRATOS_REGISTER_RESPONSE resp =
            (PKRATOS_REGISTER_RESPONSE)buffer;

        resp->Status = regStatus;
        resp->TablePointer = (PVOID)g_CanaryTable;
        resp->ProcessCallbackAddress = (PVOID)DetectorOneCreateProcessNotify;
        resp->ImageCallbackAddress = (PVOID)DetectorOneLoadImageNotify;
        resp->ThreadCallbackAddress = (PVOID)DetectorOneCreateThreadNotify;
        resp->ProcessEventCounterPtr = (PVOID)&g_ProcessEventCounter;
        resp->ImageEventCounterPtr = (PVOID)&g_ImageEventCounter;

        bytesReturned = sizeof(KRATOS_REGISTER_RESPONSE);

        DbgPrint("[DetectorOne] IOCTL_REGISTER: Canary%lu "
            "Status=0x%08X TablePtr=%p "
            "ProcessCb=%p ImageCb=%p\n",
            reqCopy.CanaryId,
            regStatus,
            g_CanaryTable,
            resp->ProcessCallbackAddress,
            resp->ImageCallbackAddress);
        break;
    }

    case IOCTL_KRATOS_TEST_SIGNAL_A:
    {
        UNREFERENCED_PARAMETER(buffer);
        UNREFERENCED_PARAMETER(inputLen);
        UNREFERENCED_PARAMETER(outputLen);

        status = DetectorOneTestSignalA();
        bytesReturned = 0;
        break;
    }

    case IOCTL_KRATOS_GET_EVENTS:
    {
        UNREFERENCED_PARAMETER(inputLen);
        if (outputLen < sizeof(DETECTORONE_EVENT_BATCH)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        bytesReturned = DetectorOneDrainTelemetryEvents(
            (PDETECTORONE_EVENT_BATCH)buffer, outputLen);
        status = STATUS_SUCCESS;
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// Create/close handler required so canaries can open the DetectorOne device.
NTSTATUS DetectorOneDispatchCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}




