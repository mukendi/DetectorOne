#include "header.h"

// DetectorOne BYOVD IAT analysis, registry pre-load filtering and service tracking.

WCHAR DetectorOneUpcaseWideChar(WCHAR c) {
    return (c >= L'a' && c <= L'z') ? (WCHAR)(c - (L'a' - L'A')) : c;
}

BOOLEAN DetectorOneIsSysDriverName(IN PUNICODE_STRING FullImageName) {
    if (!FullImageName || !FullImageName->Buffer ||
        FullImageName->Length < (4 * sizeof(WCHAR))) return FALSE;

    PWCHAR suffix = FullImageName->Buffer +
        (FullImageName->Length / sizeof(WCHAR)) - 4;
    return (suffix[0] == L'.' &&
        (suffix[1] == L's' || suffix[1] == L'S') &&
        (suffix[2] == L'y' || suffix[2] == L'Y') &&
        (suffix[3] == L's' || suffix[3] == L'S'));
}

BOOLEAN DetectorOneIsDriverFromSystem32Drivers(IN PUNICODE_STRING Name) {
    if (!Name || !Name->Buffer) return FALSE;
    return DetectorOneUnicodeContainsInsensitive(
        Name, L"\\WINDOWS\\SYSTEM32\\DRIVERS\\");
}

BOOLEAN DetectorOneUnicodeContainsInsensitive(
    IN PCUNICODE_STRING Text, IN PCWSTR Pattern)
{
    if (!Text || !Text->Buffer || !Pattern) return FALSE;

    SIZE_T textLen = Text->Length / sizeof(WCHAR);
    SIZE_T patternLen = 0;
    while (Pattern[patternLen] != L'\0') patternLen++;

    if (!patternLen || patternLen > textLen) return FALSE;

    for (SIZE_T i = 0; i <= textLen - patternLen; i++) {
        SIZE_T j = 0;
        for (; j < patternLen; j++) {
            if (DetectorOneUpcaseWideChar(Text->Buffer[i + j]) !=
                DetectorOneUpcaseWideChar(Pattern[j])) break;
        }
        if (j == patternLen) return TRUE;
    }
    return FALSE;
}

BOOLEAN DetectorOneUnicodeEqualsInsensitive(
    IN PCUNICODE_STRING Text, IN PCWSTR Pattern)
{
    if (!Text || !Text->Buffer || !Pattern) return FALSE;

    SIZE_T textLen = Text->Length / sizeof(WCHAR);
    SIZE_T patternLen = 0;
    while (Pattern[patternLen] != L'\0') patternLen++;

    if (textLen != patternLen) return FALSE;

    for (SIZE_T i = 0; i < textLen; i++) {
        if (DetectorOneUpcaseWideChar(Text->Buffer[i]) !=
            DetectorOneUpcaseWideChar(Pattern[i])) return FALSE;
    }
    return TRUE;
}

VOID DetectorOneLogRegistryServiceEvent(
    IN PCSTR Operation, IN PCUNICODE_STRING KeyName,
    IN PCUNICODE_STRING ValueName, IN ULONG Type, IN ULONG DataSize)
{
    HANDLE currentPid = PsGetCurrentProcessId();
    PCSTR currentImage =
        (PCSTR)PsGetProcessImageFileName(PsGetCurrentProcess());
    if (!currentImage) currentImage = "<unknown>";

    // Surface service registry writes to DetectorOneEngine. The key path is
    // carried in ImagePath for the shared telemetry ABI; Address and RegionSize
    // carry registry Type and DataSize respectively.
    DetectorOneQueueTelemetryEventEx(
        DETECTORONE_EVENT_REGISTRY_SERVICE,
        (ULONG64)(ULONG_PTR)currentPid,
        0,
        0,
        (ULONG64)Type,
        (ULONG64)DataSize,
        0,
        KeyName,
        L"service-registry",
        0,
        0);

   
    if (ValueName) {
        
        DbgPrint("[DetectorOne] Registry %s Pid=%llu Image=%s "
            "Type=%lu Size=%lu Key=%wZ Value=%wZ\n",
            Operation, (ULONG_PTR)currentPid, currentImage,
            Type, DataSize, KeyName, ValueName);
    }
    else {
        DbgPrint("[DetectorOne] Registry %s Pid=%llu Image=%s "
            "Key=%wZ\n",
            Operation, (ULONG_PTR)currentPid, currentImage, KeyName);
    }
}


BOOLEAN DetectorOneIsImageRangeValid(
    IN SIZE_T ImageSize, IN ULONG Rva, IN SIZE_T Length)
{
    if (!Length || Rva > ImageSize) return FALSE;
    return Length <= (ImageSize - Rva);
}

INT DetectorOneAsciiCompareInsensitive(IN PCSTR First, IN PCSTR Second) {
    while (*First != '\0' && *Second != '\0') {
        CHAR a = *First, b = *Second;
        if (a >= 'A' && a <= 'Z') a = (CHAR)(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = (CHAR)(b + ('a' - 'A'));
        if (a != b) return (INT)((UCHAR)a - (UCHAR)b);
        First++; Second++;
    }
    return (INT)((UCHAR)*First - (UCHAR)*Second);
}

VOID DetectorOneScoreImport(IN PCSTR FunctionName, IN PCSTR DllName,IN OUT PDETECTORONE_IAT_SCORE Score, IN OUT PDETECTORONE_IAT_CAPABILITIES Caps)
{
    for (ULONG i = 0; g_DangerousImports[i].FunctionName != NULL; i++) {
        if (DetectorOneAsciiCompareInsensitive(
            FunctionName,
            g_DangerousImports[i].FunctionName) != 0) continue;

        PCSTR category = g_DangerousImports[i].Category;
        ULONG weight = g_DangerousImports[i].Weight;

        if (DetectorOneAsciiCompareInsensitive(
            FunctionName, "ZwTerminateProcess") == 0) {
            Score->ImportsZwTerminateProcess = TRUE;
            Caps->HasProcessTerminate = TRUE;
        }
        else if (DetectorOneAsciiCompareInsensitive(
            FunctionName, "MmMapIoSpace") == 0) {
            Score->ImportsMmMapIoSpace = TRUE;
            Caps->HasMemoryAccess = TRUE;
        }
        else if (DetectorOneAsciiCompareInsensitive(
            FunctionName, "MmGetPhysicalAddress") == 0) {
            Score->ImportsMmGetPhysicalAddress = TRUE;
            Caps->HasMemoryAccess = TRUE;
        }
        else if (DetectorOneAsciiCompareInsensitive(
            FunctionName, "ZwMapViewOfSection") == 0) {
            Score->ImportsZwMapViewOfSection = TRUE;
            Caps->HasMemoryAccess = TRUE;
        }

        if (DetectorOneAsciiCompareInsensitive(
            FunctionName, "ZwOpenProcess") == 0 ||
            DetectorOneAsciiCompareInsensitive(
                FunctionName, "NtOpenProcess") == 0) {
            Caps->HasProcessOpen = TRUE;
        }

        if (DetectorOneAsciiCompareInsensitive(
            FunctionName, "ZwQuerySystemInformation") == 0) {
            Caps->HasProcessEnum = TRUE;
        }

        if (DetectorOneAsciiCompareInsensitive(
            category, "CALLBACK_REMOVAL") == 0)
            Caps->HasCallbackRemoval = TRUE;

        if (DetectorOneAsciiCompareInsensitive(
            category, "MSR_ACCESS") == 0)
            Caps->HasMsrAccess = TRUE;

        if (DetectorOneAsciiCompareInsensitive(
            category, "PHYSICAL_MEMORY") == 0 ||
            DetectorOneAsciiCompareInsensitive(
                category, "MEMORY_MAPPING") == 0)
            Score->MemoryAccess += weight;
        else if (DetectorOneAsciiCompareInsensitive(
            category, "PROCESS_ACCESS") == 0 ||
            DetectorOneAsciiCompareInsensitive(
                category, "PROCESS_KILL") == 0)
            Score->ProcessInteraction += weight;
        else if (DetectorOneAsciiCompareInsensitive(
            category, "CALLBACK_MANIP") == 0 ||
            DetectorOneAsciiCompareInsensitive(
                category, "CALLBACK_REMOVAL") == 0)
            Score->CallbackInteraction += weight;
        else
            Score->KernelManipulation += weight;

        Score->DangerousTotal += weight;

        DbgPrint("[DetectorOne] Sensitive import: %s from %s "
            "Weight=%lu\n",
            FunctionName,
            DllName ? DllName : "<unknown>", weight);
    }
}

ULONG DetectorOneDetectDangerousCombinations(
    IN PDETECTORONE_IAT_CAPABILITIES Caps,
    IN PDETECTORONE_IAT_SCORE Score)
{
    UNREFERENCED_PARAMETER(Score);
    ULONG bonus = 0;

    if (Caps->HasProcessOpen && Caps->HasProcessTerminate) {
        bonus += 100;
        DbgPrint("[DetectorOne] COMBO: EDR Process Killer\n");
    }
    if (Caps->HasProcessEnum && Caps->HasProcessOpen &&
        Caps->HasProcessTerminate) {
        bonus += 150;
        DbgPrint("[DetectorOne] COMBO: Process Hunt and Kill\n");
    }
    if (Caps->HasMemoryAccess && Caps->HasProcessTerminate) {
        bonus += 120;
        DbgPrint("[DetectorOne] COMBO: Physical Memory + Kill\n");
    }
    if (Caps->HasCallbackRemoval && Caps->HasProcessTerminate) {
        bonus += 130;
        DbgPrint("[DetectorOne] COMBO: Callback Removal + Kill\n");
    }
    if (Caps->HasProcessTerminate && Caps->HasCallbackRemoval &&
        Caps->HasMemoryAccess) {
        bonus += 200;
        DbgPrint("[DetectorOne] COMBO: Full EDR Blinding Kit\n");
    }
    if (Caps->HasMsrAccess && Caps->HasProcessTerminate) {
        bonus += 140;
        DbgPrint("[DetectorOne] COMBO: MSR + Kill\n");
    }
    return bonus;
}

NTSTATUS DetectorOneAnalyzeDriverIAT(
    IN  PVOID                           ImageBase,
    IN  SIZE_T                          ImageSize,
    OUT PDETECTORONE_IAT_SCORE          Score,
    OUT PULONG                          TotalRiskScore,
    OUT PDETECTORONE_IAT_CAPABILITIES   OutCaps)
{
    if (!ImageBase || !Score || !TotalRiskScore || !OutCaps ||
        ImageSize < sizeof(IMAGE_DOS_HEADER))
        return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(Score, sizeof(*Score));
    RtlZeroMemory(OutCaps, sizeof(*OutCaps));
    *TotalRiskScore = 0;
    DETECTORONE_IAT_CAPABILITIES caps = { 0 };

    __try {
        PUCHAR image = (PUCHAR)ImageBase;
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)image;

        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0)
            return STATUS_INVALID_IMAGE_FORMAT;

        if (!DetectorOneIsImageRangeValid(ImageSize,
            (ULONG)dos->e_lfanew, sizeof(IMAGE_NT_HEADERS64)))
            return STATUS_INVALID_IMAGE_FORMAT;

        PIMAGE_NT_HEADERS64 nt =
            (PIMAGE_NT_HEADERS64)(image + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            return STATUS_INVALID_IMAGE_FORMAT;

        IMAGE_DATA_DIRECTORY importDir =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!importDir.VirtualAddress || !importDir.Size)
            return STATUS_SUCCESS;

        if (!DetectorOneIsImageRangeValid(ImageSize,
            importDir.VirtualAddress, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
            return STATUS_INVALID_IMAGE_FORMAT;

        PIMAGE_IMPORT_DESCRIPTOR desc =
            (PIMAGE_IMPORT_DESCRIPTOR)(image + importDir.VirtualAddress);
        ULONG maxDesc = importDir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (!maxDesc) return STATUS_INVALID_IMAGE_FORMAT;

        for (ULONG di = 0; di < maxDesc; di++, desc++) {
            if (!desc->Name && !desc->FirstThunk &&
                !desc->OriginalFirstThunk) break;

            PCSTR dllName = "<unknown>";
            if (DetectorOneIsImageRangeValid(ImageSize, desc->Name, 1))
                dllName = (PCSTR)(image + desc->Name);

            ULONG thunkRva = desc->OriginalFirstThunk
                ? desc->OriginalFirstThunk : desc->FirstThunk;

            if (!DetectorOneIsImageRangeValid(
                ImageSize, thunkRva, sizeof(IMAGE_THUNK_DATA64)))
                continue;

            PIMAGE_THUNK_DATA64 thunk =
                (PIMAGE_THUNK_DATA64)(image + thunkRva);
            ULONG maxThunk =
                (ULONG)((ImageSize - thunkRva) / sizeof(IMAGE_THUNK_DATA64));

            for (ULONG ti = 0; ti < maxThunk; ti++, thunk++) {
                if (!thunk->u1.AddressOfData) break;
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) continue;
                if (thunk->u1.AddressOfData > MAXULONG) continue;

                ULONG ibnRva = (ULONG)thunk->u1.AddressOfData;
                if (!DetectorOneIsImageRangeValid(
                    ImageSize, ibnRva, sizeof(IMAGE_IMPORT_BY_NAME)) ||
                    !DetectorOneIsImageRangeValid(
                        ImageSize,
                        ibnRva + FIELD_OFFSET(IMAGE_IMPORT_BY_NAME, Name),
                        sizeof(CHAR)))
                    continue;

                PIMAGE_IMPORT_BY_NAME ibn =
                    (PIMAGE_IMPORT_BY_NAME)(image + ibnRva);

                // caps est remplie ici par DetectorOneScoreImport
                DetectorOneScoreImport(
                    (PCSTR)ibn->Name, dllName, Score, &caps);
            }
        }

        ULONG base =
            (Score->MemoryAccess * 2) +
            (Score->ProcessInteraction * 2) +
            (Score->KernelManipulation * 3) +
            (Score->CallbackInteraction * 3) +
            Score->DangerousTotal;

        ULONG combo =
            DetectorOneDetectDangerousCombinations(&caps, Score);

        *TotalRiskScore = base + combo;

        if (combo) {
            DbgPrint("[DetectorOne] IAT combo: base=%lu bonus=%lu "
                "total=%lu\n", base, combo, *TotalRiskScore);
        }

        // Return the computed capabilities to the policy caller.
        *OutCaps = caps;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        NTSTATUS ex = GetExceptionCode();
        DbgPrint("[DetectorOne] IAT exception: 0x%08X\n", ex);
        return ex;
    }

    return STATUS_SUCCESS;
}
static PVOID DetectorOneRvaToFilePointer(
    IN PUCHAR FileBase,
    IN SIZE_T FileSize,
    IN PIMAGE_NT_HEADERS64 Nt,
    IN ULONG Rva,
    IN SIZE_T RequiredLength
) {
    if (!FileBase || !Nt || !RequiredLength) return NULL;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(Nt);
    for (USHORT i = 0; i < Nt->FileHeader.NumberOfSections; i++, section++) {
        ULONG virtualSize = section->Misc.VirtualSize;
        ULONG rawSize = section->SizeOfRawData;
        ULONG sectionSpan = virtualSize > rawSize ? virtualSize : rawSize;

        if (!sectionSpan) continue;
        if (Rva < section->VirtualAddress ||
            Rva >= section->VirtualAddress + sectionSpan) {
            continue;
        }

        ULONG delta = Rva - section->VirtualAddress;
        if (delta >= rawSize) return NULL;

        ULONG fileOffset = section->PointerToRawData + delta;
        if (!DetectorOneIsImageRangeValid(FileSize, fileOffset, RequiredLength))
            return NULL;

        return FileBase + fileOffset;
    }

    if (DetectorOneIsImageRangeValid(FileSize, Rva, RequiredLength))
        return FileBase + Rva;

    return NULL;
}

NTSTATUS DetectorOneAnalyzeDriverIATFromFile(
    IN  PVOID                           FileBase,
    IN  SIZE_T                          FileSize,
    OUT PDETECTORONE_IAT_SCORE          Score,
    OUT PULONG                          TotalRiskScore,
    OUT PDETECTORONE_IAT_CAPABILITIES   OutCaps
) {
    if (!FileBase || !Score || !TotalRiskScore || !OutCaps ||
        FileSize < sizeof(IMAGE_DOS_HEADER))
        return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(Score, sizeof(*Score));
    RtlZeroMemory(OutCaps, sizeof(*OutCaps));
    *TotalRiskScore = 0;
    DETECTORONE_IAT_CAPABILITIES caps = { 0 };

    __try {
        PUCHAR file = (PUCHAR)FileBase;
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)file;

        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0)
            return STATUS_INVALID_IMAGE_FORMAT;

        if (!DetectorOneIsImageRangeValid(
            FileSize, (ULONG)dos->e_lfanew, sizeof(IMAGE_NT_HEADERS64)))
            return STATUS_INVALID_IMAGE_FORMAT;

        PIMAGE_NT_HEADERS64 nt =
            (PIMAGE_NT_HEADERS64)(file + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            return STATUS_INVALID_IMAGE_FORMAT;

        IMAGE_DATA_DIRECTORY importDir =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!importDir.VirtualAddress || !importDir.Size)
            return STATUS_SUCCESS;

        PIMAGE_IMPORT_DESCRIPTOR desc =
            (PIMAGE_IMPORT_DESCRIPTOR)DetectorOneRvaToFilePointer(
                file, FileSize, nt, importDir.VirtualAddress,
                sizeof(IMAGE_IMPORT_DESCRIPTOR));
        if (!desc) return STATUS_INVALID_IMAGE_FORMAT;

        ULONG maxDesc = importDir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (!maxDesc) return STATUS_INVALID_IMAGE_FORMAT;

        for (ULONG di = 0; di < maxDesc; di++, desc++) {
            if (!DetectorOneIsImageRangeValid(
                FileSize, (ULONG)((PUCHAR)desc - file),
                sizeof(IMAGE_IMPORT_DESCRIPTOR)))
                break;

            if (!desc->Name && !desc->FirstThunk &&
                !desc->OriginalFirstThunk) break;

            PCSTR dllName = "<unknown>";
            PCHAR dllNamePtr = (PCHAR)DetectorOneRvaToFilePointer(
                file, FileSize, nt, desc->Name, sizeof(CHAR));
            if (dllNamePtr) dllName = dllNamePtr;

            ULONG thunkRva = desc->OriginalFirstThunk
                ? desc->OriginalFirstThunk : desc->FirstThunk;

            PIMAGE_THUNK_DATA64 thunk =
                (PIMAGE_THUNK_DATA64)DetectorOneRvaToFilePointer(
                    file, FileSize, nt, thunkRva,
                    sizeof(IMAGE_THUNK_DATA64));
            if (!thunk) continue;

            for (ULONG ti = 0; ti < 4096; ti++, thunk++) {
                if (!DetectorOneIsImageRangeValid(
                    FileSize, (ULONG)((PUCHAR)thunk - file),
                    sizeof(IMAGE_THUNK_DATA64)))
                    break;

                if (!thunk->u1.AddressOfData) break;
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) continue;
                if (thunk->u1.AddressOfData > MAXULONG) continue;

                PIMAGE_IMPORT_BY_NAME ibn =
                    (PIMAGE_IMPORT_BY_NAME)DetectorOneRvaToFilePointer(
                        file, FileSize, nt,
                        (ULONG)thunk->u1.AddressOfData,
                        sizeof(IMAGE_IMPORT_BY_NAME));
                if (!ibn) continue;

                DetectorOneScoreImport(
                    (PCSTR)ibn->Name, dllName, Score, &caps);
            }
        }

        ULONG base =
            (Score->MemoryAccess * 2) +
            (Score->ProcessInteraction * 2) +
            (Score->KernelManipulation * 3) +
            (Score->CallbackInteraction * 3) +
            Score->DangerousTotal;

        ULONG combo =
            DetectorOneDetectDangerousCombinations(&caps, Score);

        *TotalRiskScore = base + combo;
        *OutCaps = caps;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        NTSTATUS ex = GetExceptionCode();
        DbgPrint("[DetectorOne] File IAT exception: 0x%08X\n", ex);
        return ex;
    }

    return STATUS_SUCCESS;
}
// Test-only path: simulates EDR blinding by removing DetectorOne's
// process creation callback while leaving the canary baseline intact.
BYOVD_PRIMITIVE_CATEGORY KratosClassifyPrimitive(
    IN PDETECTORONE_IAT_SCORE Score,
    IN PDETECTORONE_IAT_CAPABILITIES Caps
) {
    // Category 3: pure process killer.
    // ZwTerminateProcess is present without a physical-memory primitive.

    if (Score->ImportsZwTerminateProcess &&
        !Score->ImportsMmMapIoSpace &&
        !Score->ImportsMmGetPhysicalAddress) {
        return PRIMITIVE_DRIVER_KILLER;
    }

    // Category 2: MSR or port I/O access.
    if (Caps->HasMsrAccess) {
        return PRIMITIVE_MSR_PORT_IO;
    }

    // Category 1: physical-memory access.
    if (Score->ImportsMmMapIoSpace ||
        (Score->ImportsMmGetPhysicalAddress &&
            Score->ImportsZwMapViewOfSection)) {
        return PRIMITIVE_PHYSICAL_MEMORY;
    }

    // Category 4: arbitrary read/write style mapping.
    if (Score->ImportsZwMapViewOfSection &&
        Score->MemoryAccess > 0) {
        return PRIMITIVE_ARBITRARY_RW;
    }

    // Combined categories raise the alert severity.
    if (Caps->HasProcessTerminate &&
        (Caps->HasMemoryAccess || Caps->HasMsrAccess)) {
        return PRIMITIVE_COMBO;
    }

    return PRIMITIVE_UNKNOWN;
}

/**
 * @brief Force-unload a suspicious driver when policy allows it.
 * @param FullImageName Full image path of the suspicious driver.
 */
NTSTATUS KratosForceUnloadDriver(IN PUNICODE_STRING FullImageName)
{
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING serviceRegPath;
    WCHAR regPathBuffer[512] = { 0 };

    if (!FullImageName || !FullImageName->Buffer) {
        return STATUS_INVALID_PARAMETER;
    }

    // Extract the service name from the driver image file name.
    UNICODE_STRING driverName;
    USHORT lastSlash = 0;
    USHORT dotPos = 0;

    for (USHORT i = 0; i < FullImageName->Length / sizeof(WCHAR); i++) {
        if (FullImageName->Buffer[i] == L'\\') lastSlash = i;
        if (FullImageName->Buffer[i] == L'.') dotPos = i;
    }

    if (dotPos <= lastSlash) {
        dotPos = FullImageName->Length / sizeof(WCHAR);
    }

    USHORT nameLength = (dotPos - lastSlash - 1) * sizeof(WCHAR);
    driverName.Buffer = &FullImageName->Buffer[lastSlash + 1];
    driverName.Length = nameLength;
    driverName.MaximumLength = nameLength;

    // Rebuild the registry service path required by ZwUnloadDriver:
    // "\Registry\Machine\System\CurrentControlSet\Services\<DriverName>"
    RtlInitEmptyUnicodeString(&serviceRegPath, regPathBuffer, sizeof(regPathBuffer));
    status = RtlUnicodeStringPrintf(
        &serviceRegPath,
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%.*s",
        driverName.Length / sizeof(WCHAR),
        driverName.Buffer
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[DetectorOne] Error constructing registry path for unload: 0x%X\n", status);
        return status;
    }

    DbgPrint("[DetectorOne] Attempting ZwUnloadDriver for service: %wZ\n", &serviceRegPath);

    // ZwUnloadDriver must run at PASSIVE_LEVEL.
    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        status = ZwUnloadDriver(&serviceRegPath);
        if (NT_SUCCESS(status)) {
            DbgPrint("[DetectorOne] Successfully unloaded driver: %wZ\n", &serviceRegPath);
        }
        else {
            DbgPrint("[DetectorOne] Failed to unload driver: %wZ (Status: 0x%X)\n", &serviceRegPath, status);
        }
    }
    else {
        DbgPrint("[DetectorOne] Cannot call ZwUnloadDriver: High IRQL (%d)\n", KeGetCurrentIrql());
        status = STATUS_UNSUCCESSFUL;
    }

    return status;
}
VOID KratosHandleHighRiskDriver(
    IN PUNICODE_STRING          FullImageName,
    IN PDETECTORONE_IAT_SCORE   IatScore,
    IN PDETECTORONE_IAT_CAPABILITIES Caps,
    IN ULONG                    TotalRiskScore
) {
    BYOVD_PRIMITIVE_CATEGORY category =
        KratosClassifyPrimitive(IatScore, Caps);

    DbgPrint("[DetectorOne] Primitive category: %lu Driver=%wZ\n",
        (ULONG)category, FullImageName);

    switch (category) {

    case PRIMITIVE_DRIVER_KILLER:
        // Category 3 policy: unload immediately.
        // No canary persistence window is needed for this direct EDR-killer case.
        // The threat model is targeted and immediate.
        DbgPrint("[DetectorOne] DRIVER KILLER detected — enforcing immediate unload: %wZ\n", FullImageName);

        KratosForceUnloadDriver(FullImageName);
        // Keep the security log, but do not dispatch a canary alert.
        break;

    case PRIMITIVE_PHYSICAL_MEMORY:
    case PRIMITIVE_MSR_PORT_IO:
    case PRIMITIVE_ARBITRARY_RW:
    case PRIMITIVE_COMBO:
    default:
        // Categories 1, 2, 4 and combos require full canary surveillance.
        // These primitives can support long-lived kernel exploitation.
        // Canaries should observe the driver over time.

        if (g_CanaryTable) {
            InterlockedExchange(
                &g_CanaryTable->SuspectDriverStillLoaded, 1);

            if (FullImageName && FullImageName->Buffer) {
                RtlStringCchCopyW(
                    g_CanaryTable->SuspectDriverTracked,
                    ARRAYSIZE(g_CanaryTable->SuspectDriverTracked),
                    FullImageName->Buffer);
            }
        }

        LARGE_INTEGER loadTime;
        KeQuerySystemTime(&loadTime);

        KratosDispatchAlertToCanaries(
            FullImageName, &loadTime, TotalRiskScore);
        break;
    }
}

NTSTATUS KratosReadAndAnalyzeDriverOnDisk(
    IN  PCWSTR      ImagePathValue,  // valeur brute depuis registry
    OUT PULONG      RiskScore,
    OUT PDETECTORONE_IAT_SCORE      IatScore,
    OUT PDETECTORONE_IAT_CAPABILITIES IatCaps
) {
    NTSTATUS status;
    UNICODE_STRING filePath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK ioStatus;
    HANDLE hFile = NULL;
    PVOID fileBuffer = NULL;

    RtlZeroMemory(IatScore, sizeof(*IatScore));
    RtlZeroMemory(IatCaps, sizeof(*IatCaps));
    *RiskScore = 0;

    WCHAR ntPathBuf[KRATOS_IMAGE_PATH_MAX] = { 0 };

    if (_wcsnicmp(ImagePathValue, L"\\SystemRoot\\", 12) == 0) {

        RtlStringCchCatW(ntPathBuf, ARRAYSIZE(ntPathBuf), ImagePathValue + 12);
    }
    else if (ImagePathValue[0] == L'\\' &&
        ImagePathValue[1] != L'?') {
        RtlStringCchCopyW(ntPathBuf, ARRAYSIZE(ntPathBuf),
            ImagePathValue);
    }
    else {

        RtlStringCchCatW(ntPathBuf, ARRAYSIZE(ntPathBuf), ImagePathValue);
    }

    RtlInitUnicodeString(&filePath, ntPathBuf);
    InitializeObjectAttributes(&oa, &filePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL, NULL);

    // Ouvrir le fichier en lecture seule
    status = ZwCreateFile(
        &hFile,
        GENERIC_READ | SYNCHRONIZE,
        &oa,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL, 0
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[DetectorOne] Cannot open %S for IAT analysis: "
            "0x%08X\n", ntPathBuf, status);
        return status;
    }

    // Query the driver file size before allocating a kernel buffer.
    FILE_STANDARD_INFORMATION fileInfo = { 0 };
    status = ZwQueryInformationFile(
        hFile, &ioStatus, &fileInfo,
        sizeof(fileInfo), FileStandardInformation);

    if (!NT_SUCCESS(status) ||
        fileInfo.EndOfFile.QuadPart == 0 ||
        fileInfo.EndOfFile.QuadPart > 10 * 1024 * 1024) {
        // Refuse unusually large files to limit kernel memory exposure.
        DbgPrint("[DetectorOne] Invalid file size for %S\n", ntPathBuf);
        ZwClose(hFile);
        return STATUS_FILE_TOO_LARGE;
    }

    SIZE_T fileSize = (SIZE_T)fileInfo.EndOfFile.QuadPart;

    // Allocate a nonpaged buffer for the complete driver file.
    fileBuffer = ExAllocatePool2(
        POOL_FLAG_NON_PAGED, fileSize, POOL_TAG);
    if (!fileBuffer) {
        ZwClose(hFile);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Read the complete file so the PE/IAT parser can range-check locally.
    LARGE_INTEGER offset = { 0 };
    status = ZwReadFile(
        hFile, NULL, NULL, NULL, &ioStatus,
        fileBuffer, (ULONG)fileSize,
        &offset, NULL);

    ZwClose(hFile);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[DetectorOne] Cannot read %S: 0x%08X\n",
            ntPathBuf, status);
        ExFreePoolWithTag(fileBuffer, POOL_TAG);
        return status;
    }

    // Analyze the raw on-disk PE file. This path must translate RVAs through sections.
    status = DetectorOneAnalyzeDriverIATFromFile(
        fileBuffer, fileSize,
        IatScore, RiskScore, IatCaps);

    DbgPrint("[DetectorOne] Pre-load IAT analysis: %S Risk=%lu "
        "ZwTerminate=%u MmMapIoSpace=%u\n",
        ntPathBuf, *RiskScore,
        (ULONG)IatScore->ImportsZwTerminateProcess,
        (ULONG)IatScore->ImportsMmMapIoSpace);

    ExFreePoolWithTag(fileBuffer, POOL_TAG);
    return status;
}

NTSTATUS KratosFindServicePath(IN  PUNICODE_STRING DriverImagePath, OUT PUNICODE_STRING ServicePath)
{
    if (!DriverImagePath || !ServicePath) return STATUS_INVALID_PARAMETER;

    PWCHAR imagePathStr = DriverImagePath->Buffer;
    if (!imagePathStr) return STATUS_INVALID_PARAMETER;

    PCWSTR targetBase = ExtractBaseName(imagePathStr);
    if (!targetBase || !*targetBase) return STATUS_NOT_FOUND;

    DbgPrint("[DetectorOne] KratosFindServicePath: looking for %S\n",
        targetBase);

    NTSTATUS status = STATUS_NOT_FOUND;

    ExAcquireFastMutex(&g_ServiceTableLock);
    DbgPrint("[DetectorOne] ServiceTable dump (%lu entries):\n",
        g_ServiceTableIndex);
    for (ULONG i = 0; i < KRATOS_MAX_SERVICE_ENTRIES; i++) {
        PKRATOS_SERVICE_ENTRY entry = &g_ServiceTable[i];
        if (!entry->Valid) continue;

        DbgPrint("[DetectorOne]   [%lu] Name=%S ImagePath=%S\n",
            i,
            g_ServiceTable[i].ServiceName,
            g_ServiceTable[i].ImagePath);
        // Comparer le nom de service avec le nom de base du driver
        // entry->ServiceName = "k7rkscan"
        // targetBase         = "k7rkscan.sys"
        if (!BaseNamesMatch(entry->ServiceName, targetBase)) {
            // Also try matching against the stored ImagePath.
            PCWSTR entryBase = ExtractBaseName(entry->ImagePath);
            if (!entryBase || !BaseNamesMatch(entryBase, targetBase))
                continue;
        }

        // Match found: allocate and return the service registry path.
        SIZE_T pathLen = wcslen(entry->ServicePath);
        SIZE_T allocSize = (pathLen + 1) * sizeof(WCHAR);

        PWCHAR buffer = (PWCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, allocSize, POOL_TAG);

        if (!buffer) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        RtlCopyMemory(buffer, entry->ServicePath, allocSize);

        ServicePath->Buffer = buffer;
        ServicePath->Length = (USHORT)(pathLen * sizeof(WCHAR));
        ServicePath->MaximumLength = (USHORT)allocSize;

        //DbgPrint("[DetectorOne] KratosFindServicePath: found %S -> %S\n", targetBase, buffer);

        status = STATUS_SUCCESS;
        break;
    }

    ExReleaseFastMutex(&g_ServiceTableLock);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[DetectorOne] KratosFindServicePath: "
            "no service found for %S\n", targetBase);
    }

    return status;
}
PCWSTR ExtractBaseName(IN PCWSTR FullPath) {
    if (!FullPath) return NULL;
    PCWSTR last = FullPath;
    for (PCWSTR p = FullPath; *p; p++) {
        if (*p == L'\\') last = p + 1;
    }
    return last;
}

BOOLEAN BaseNamesMatch(IN PCWSTR Name1, IN PCWSTR Name2) {
    // Comparer sans extension
    SIZE_T len1 = wcslen(Name1);
    SIZE_T len2 = wcslen(Name2);

    // Remove the .sys suffix when present.
    if (len1 >= 4) {
        WCHAR last4_1[5] = { 0 };
        RtlCopyMemory(last4_1, Name1 + len1 - 4, 4 * sizeof(WCHAR));
        // Upcase
        for (int i = 0; i < 4; i++)
            if (last4_1[i] >= L'a' && last4_1[i] <= L'z')
                last4_1[i] -= (L'a' - L'A');
        if (RtlCompareMemory(last4_1, L".SYS", 8) == 8)
            len1 -= 4;
    }
    if (len2 >= 4) {
        WCHAR last4_2[5] = { 0 };
        RtlCopyMemory(last4_2, Name2 + len2 - 4, 4 * sizeof(WCHAR));
        for (int i = 0; i < 4; i++)
            if (last4_2[i] >= L'a' && last4_2[i] <= L'z')
                last4_2[i] -= (L'a' - L'A');
        if (RtlCompareMemory(last4_2, L".SYS", 8) == 8)
            len2 -= 4;
    }

    if (len1 != len2) return FALSE;

    for (SIZE_T i = 0; i < len1; i++) {
        WCHAR a = Name1[i], b = Name2[i];
        if (a >= L'a' && a <= L'z') a -= (L'a' - L'A');
        if (b >= L'a' && b <= L'z') b -= (L'a' - L'A');
        if (a != b) return FALSE;
    }
    return TRUE;
}


// KratosStoreServiceEntry
//
// Store the relationship between a driver service registry key
// and the corresponding driver image path.
//
// Called from the registry callback when ImagePath is written.
// Used later by KratosFindServicePath for ZwUnloadDriver.
//
// Parameters :
//   KeyName        - full registry key path
//                    \REGISTRY\MACHINE\SYSTEM\...\Services\k7rkscan
//   ImagePathValue - raw ImagePath value
//                    \SystemRoot\System32\drivers\k7rkscan.sys
//   Blocked        - TRUE if the pre-load policy blocked it


VOID KratosStoreServiceEntry(
    IN PCUNICODE_STRING KeyName,
    IN PCWSTR           ImagePathValue,
    IN BOOLEAN          Blocked
) {
    if (!KeyName || !KeyName->Buffer || !ImagePathValue) return;

    // Extract the service name from the registry key path.
                                              
    PCWSTR servicesMarker = L"\\Services\\";
    SIZE_T markerLen = wcslen(servicesMarker);
    SIZE_T keyLen = KeyName->Length / sizeof(WCHAR);

    PWCHAR serviceNameStart = NULL;

    for (SIZE_T i = 0; i <= keyLen - markerLen; i++) {
        BOOLEAN match = TRUE;
        for (SIZE_T j = 0; j < markerLen; j++) {
            WCHAR a = KeyName->Buffer[i + j];
            WCHAR b = servicesMarker[j];
            if (a >= L'a' && a <= L'z') a -= (L'a' - L'A');
            if (b >= L'a' && b <= L'z') b -= (L'a' - L'A');
            if (a != b) { match = FALSE; break; }
        }
        if (match) {
            serviceNameStart = KeyName->Buffer + i + markerLen;
            break;
        }
    }

    if (!serviceNameStart) {
        DbgPrint("[DetectorOne] KratosStoreServiceEntry: "
            "cannot extract service name from %wZ\n", KeyName);
        return;
    }

    // Read until the next path separator or the end of the counted key name.
    SIZE_T serviceNameOffset = (SIZE_T)(serviceNameStart - KeyName->Buffer);
    SIZE_T serviceNameLen = 0;
    while ((serviceNameOffset + serviceNameLen) < keyLen &&
        serviceNameStart[serviceNameLen] != L'\\') {
        serviceNameLen++;
    }


    if (serviceNameLen == 0 ||
        serviceNameLen >= KRATOS_SERVICE_NAME_MAX) {
        DbgPrint("[DetectorOne] KratosStoreServiceEntry: "
            "service name too long or empty\n");
        return;
    }

    ExAcquireFastMutex(&g_ServiceTableLock);

    // Update the existing service entry if one is already present.
    PKRATOS_SERVICE_ENTRY existing = NULL;

    for (ULONG i = 0; i < KRATOS_MAX_SERVICE_ENTRIES; i++) {
        if (!g_ServiceTable[i].Valid) continue;

        // Compare service names case-insensitively.
        SIZE_T existingLen = wcslen(g_ServiceTable[i].ServiceName);
        if (existingLen != serviceNameLen) continue;

        BOOLEAN sameService = TRUE;
        for (SIZE_T j = 0; j < serviceNameLen; j++) {
            WCHAR a = g_ServiceTable[i].ServiceName[j];
            WCHAR b = serviceNameStart[j];
            if (a >= L'a' && a <= L'z') a -= (L'a' - L'A');
            if (b >= L'a' && b <= L'z') b -= (L'a' - L'A');
            if (a != b) { sameService = FALSE; break; }
        }

        if (sameService) {
            existing = &g_ServiceTable[i];
            break;
        }
    }

    // Reuse an existing slot or allocate a new one.
    PKRATOS_SERVICE_ENTRY entry = existing;

    if (!entry) {
        // Circular slot: overwrite the oldest entry if the table is full.
        ULONG idx = g_ServiceTableIndex % KRATOS_MAX_SERVICE_ENTRIES;
        entry = &g_ServiceTable[idx];
        g_ServiceTableIndex++;
    }

    // Populate the service table entry.
    RtlZeroMemory(entry, sizeof(*entry));

    // Service name, for example "k7rkscan".
    RtlCopyMemory(entry->ServiceName,
        serviceNameStart,
        serviceNameLen * sizeof(WCHAR));
    entry->ServiceName[serviceNameLen] = L'\0';

    // Full registry path used by ZwUnloadDriver:
    RtlStringCchCopyW(
        entry->ServicePath,
        KRATOS_SERVICE_NAME_MAX,
        L"\\Registry\\Machine\\System\\"
        L"CurrentControlSet\\Services\\");
    RtlStringCchCatW(
        entry->ServicePath,
        KRATOS_SERVICE_NAME_MAX,
        entry->ServiceName);

    // Raw ImagePath from the registry value.
    RtlStringCchCopyW(
        entry->ImagePath,
        KRATOS_IMAGE_PATH_MAX,
        ImagePathValue);

    // Entry metadata.
    KeQuerySystemTime(&entry->RegisterTime);
    entry->Blocked = Blocked;
    entry->Valid = TRUE;

    ExReleaseFastMutex(&g_ServiceTableLock);

    DbgPrint("[DetectorOne] KratosStoreServiceEntry: "
        "Name=%-32S ServicePath=%S Blocked=%u\n",
        entry->ServiceName,
        entry->ServicePath,
        (ULONG)Blocked);
}

// Registering a canary with DetectorOne


