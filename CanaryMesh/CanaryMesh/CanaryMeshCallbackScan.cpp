#include "CanaryMesh.h"

// ============================================================
// Kernel callback table discovery.
// ============================================================

PVOID CanaryFindCallbackTableInCode(
    IN PUCHAR FunctionAddress,
    IN PCWSTR RoutineName,
    IN PVOID TargetCallback,
    IN ULONG Depth)
{
    if (!FunctionAddress || !RoutineName || !TargetCallback) return NULL;
    if ((ULONG_PTR)FunctionAddress < 0xFFFF800000000000ULL) return NULL;
    if (!MmIsAddressValid(FunctionAddress)) return NULL;

    // Walk a small window of the registration routine and recover RIP-relative table references.
    for (ULONG i = 0; i < 2048; i++) {
        BOOLEAN ripRelative = FALSE;
        LONG disp = 0;
        PVOID candidate = NULL;

        if ((FunctionAddress[i] == 0x48 || FunctionAddress[i] == 0x4C) &&
            FunctionAddress[i + 1] == 0x8D &&
            (FunctionAddress[i + 2] >= 0x05 && FunctionAddress[i + 2] <= 0x3D &&
                (FunctionAddress[i + 2] & 0x07) == 0x05)) {
            disp = *(PLONG)(FunctionAddress + i + 3);
            candidate = FunctionAddress + i + 7 + disp;
            ripRelative = TRUE;
        }
        else if ((FunctionAddress[i] == 0x48 || FunctionAddress[i] == 0x4C) &&
            FunctionAddress[i + 1] == 0x8B &&
            (FunctionAddress[i + 2] >= 0x05 && FunctionAddress[i + 2] <= 0x3D &&
                (FunctionAddress[i + 2] & 0x07) == 0x05)) {
            disp = *(PLONG)(FunctionAddress + i + 3);
            candidate = FunctionAddress + i + 7 + disp;
            ripRelative = TRUE;
        }

        // Candidate addresses must be kernel pointers and must contain the expected callback.
        if (ripRelative) {
            if ((ULONG_PTR)candidate < 0xFFFF800000000000ULL) continue;
            if (!MmIsAddressValid(candidate)) continue;

            if (CanaryCallbackTableContains(candidate, TargetCallback, FALSE)) {
                DbgPrint("[CanaryMesh] Callback table from %S at %p contains %p\n",
                    RoutineName, candidate, TargetCallback);
                return candidate;
            }
        }

        // Follow one direct CALL to handle wrapper stubs without recursively scanning arbitrary code.
        if (Depth == 0 && FunctionAddress[i] == 0xE8) {
            LONG callDisp = *(PLONG)(FunctionAddress + i + 1);
            PUCHAR callTarget = FunctionAddress + i + 5 + callDisp;

            if ((ULONG_PTR)callTarget < 0xFFFF800000000000ULL) continue;
            if (!MmIsAddressValid(callTarget)) continue;

            candidate = CanaryFindCallbackTableInCode(
                callTarget,
                RoutineName,
                TargetCallback,
                Depth + 1);
            if (candidate) return candidate;
        }
    }

    return NULL;
}

PVOID CanaryFindCallbackTableForRoutine(
    IN PCWSTR RoutineName,
    IN PVOID TargetCallback)
{
    if (!RoutineName || !TargetCallback) return NULL;

    // Resolve only documented kernel exports, then infer the adjacent internal callback table.
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, RoutineName);
    PUCHAR fn = (PUCHAR)MmGetSystemRoutineAddress(&name);
    if (!fn) return NULL;

    PVOID table = CanaryFindCallbackTableInCode(
        fn,
        RoutineName,
        TargetCallback,
        0);

    if (!table) {
        DbgPrint("[CanaryMesh] No callback table from %S contains %p\n",
            RoutineName, TargetCallback);
    }

    return table;
}

BOOLEAN CanaryCallbackTableContains(
    IN PVOID TableAddress,
    IN PVOID TargetCallback,
    IN BOOLEAN Verbose)
{
    if (!TableAddress || !TargetCallback) return FALSE;

    // Callback table walking touches internal kernel memory; guard probes against faults.
    __try {
        PULONG_PTR table = (PULONG_PTR)TableAddress;

        for (ULONG i = 0; i < 64; i++) {
            PVOID slotAddress = &table[i];
            if (!MmIsAddressValid(slotAddress)) break;

            ULONG_PTR entry = table[i];
            if (entry == 0) continue;

            if ((PVOID)entry == TargetCallback ||
                (PVOID)(entry & ~(ULONG_PTR)0xF) == TargetCallback) {
                if (Verbose) {
                    DbgPrint("[CanaryMesh] Table=%p[%lu]: direct function=%p\n",
                        TableAddress, i, (PVOID)entry);
                }
                return TRUE;
            }

            // Many callback arrays store encoded EX_CALLBACK_ROUTINE_BLOCK pointers.
            PEX_CALLBACK_ROUTINE_BLOCK block =
                (PEX_CALLBACK_ROUTINE_BLOCK)(entry & ~(ULONG_PTR)0xF);

            if ((ULONG_PTR)block < 0xFFFF800000000000ULL) continue;
            if (!MmIsAddressValid(block)) continue;
            if (!MmIsAddressValid((PUCHAR)block + FIELD_OFFSET(EX_CALLBACK_ROUTINE_BLOCK, Function))) continue;

            PVOID functionPtr = block->Function;
            if ((ULONG_PTR)functionPtr < 0xFFFF800000000000ULL) continue;

            if (Verbose) {
                DbgPrint("[CanaryMesh] Table=%p[%lu]: raw=%p block=%p function=%p\n",
                    TableAddress, i, (PVOID)entry, block, functionPtr);
            }

            if (functionPtr == TargetCallback ||
                (PVOID)((ULONG_PTR)functionPtr & ~(ULONG_PTR)0xF) == TargetCallback) return TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (Verbose) {
            DbgPrint("[CanaryMesh] Exception in callback scan: 0x%08X\n", GetExceptionCode());
        }
        return FALSE;
    }

    return FALSE;
}

BOOLEAN CanaryVerifyCallbackPointerForRoutine(
    IN PCWSTR RoutineName,
    IN PVOID TargetCallback,
    IN OUT PVOID* CachedTable)
{
    if (!RoutineName || !TargetCallback || !CachedTable) return FALSE;

    // Cache discovered table addresses to avoid rescanning ntoskrnl code on every check.
    if (!*CachedTable) {
        *CachedTable = CanaryFindCallbackTableForRoutine(
            RoutineName,
            TargetCallback);
    }

    // Cache discovered table addresses to avoid rescanning ntoskrnl code on every check.
    if (!*CachedTable) return FALSE;

    return CanaryCallbackTableContains(*CachedTable, TargetCallback, FALSE);
}

BOOLEAN CanaryVerifyCallbackPointerInTable(IN PVOID TargetCallback) {
    if (!TargetCallback) return FALSE;

    if (CanaryVerifyCallbackPointerForRoutine(
        L"PsSetCreateProcessNotifyRoutineEx",
        TargetCallback,
        &g_ProcessCallbackTableAddress)) {
        return TRUE;
    }

    return CanaryVerifyCallbackPointerForRoutine(
        L"PsSetCreateProcessNotifyRoutine",
        TargetCallback,
        &g_ProcessCallbackTableAddress);
}

