#pragma once

#include <ntifs.h>      // Kernel APIs used by the WDM driver.
#include <ntimage.h>    // PE structures used by callback table discovery.
#include <ntstrsafe.h>  // RtlStringCchCopyW
#include <intrin.h>     // Compiler intrinsics.

#define CANARY_POOL_TAG                     'yrCK'
// Each build configuration produces one canary instance with a stable identity.
#ifndef CANARY_ID
#error "CANARY_ID must be defined in project Preprocessor Definitions (1, 2 or 3)"
#endif

#ifndef CANARY_SERVICE_NAME
#error "CANARY_SERVICE_NAME must be defined in project Preprocessor Definitions"
#endif

#define KRATOS_DEVICE_NAME    L"\\Device\\KratosEDR"

// Shared registration IOCTL exposed by DetectorOne.
#define IOCTL_KRATOS_REGISTER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, \
                                   METHOD_BUFFERED, FILE_ANY_ACCESS)

#define CanaryMesh_MAX_CANARIES             5
#define CanaryMesh_HEARTBEAT_INTERVAL_MS    2000
#define CanaryMesh_HEARTBEAT_TIMEOUT_MS     6000
#define CanaryMesh_DRIVER_POLL_INTERVAL_MS  1500
#define CanaryMesh_CALLBACK_CHECK_INTERVAL_MS 60000
#define CanaryMesh_CONSENSUS_REPORT_INTERVAL_MS 60000
#define CanaryMesh_HANDOFF_TIMEOUT_MS       15000
#define CanaryMesh_ALERT_WINDOW_MS          120000
#define CanaryMesh_LIVENESS_WINDOW_MS       10000
#define CanaryMesh_FAST_UNLOAD_THRESHOLD_MS 30000

// ============================================================
// IOCTL wire structures shared with DetectorOne.
// ============================================================
#pragma pack(push, 8)
typedef struct _KRATOS_REGISTER_REQUEST {
    ULONG   CanaryId;
    PVOID   DriverObjectAddress;
    PVOID   AlertEntryPoint;
} KRATOS_REGISTER_REQUEST, * PKRATOS_REGISTER_REQUEST;

typedef struct _KRATOS_REGISTER_RESPONSE {
    NTSTATUS    Status;
    PVOID       TablePointer;
    PVOID       ProcessCallbackAddress;
    PVOID       ImageCallbackAddress;
    PVOID       ThreadCallbackAddress;
    PVOID       ProcessEventCounterPtr;
    PVOID       ImageEventCounterPtr;
} KRATOS_REGISTER_RESPONSE, * PKRATOS_REGISTER_RESPONSE;
#pragma pack(pop)

C_ASSERT(sizeof(KRATOS_REGISTER_REQUEST) == 24);
C_ASSERT(sizeof(KRATOS_REGISTER_RESPONSE) == 56);
C_ASSERT(FIELD_OFFSET(KRATOS_REGISTER_REQUEST, AlertEntryPoint) == 16);
C_ASSERT(FIELD_OFFSET(KRATOS_REGISTER_RESPONSE, ProcessCallbackAddress) == 16);

// ============================================================
// Shared runtime types.
// ============================================================

typedef enum _CANARY_STATUS {
    CANARY_STATUS_UNKNOWN = 0,
    CANARY_STATUS_ALIVE = 1,
    CANARY_STATUS_SUSPECTED = 2,
    CANARY_STATUS_DEAD = 3
} CANARY_STATUS;

typedef enum _CanaryMesh_ALERT_TYPE {
    ALERT_NONE = 0,
    ALERT_CALLBACK_POINTER_REMOVED = 1,
    ALERT_CALLBACK_LIVENESS_FROZEN = 2,
    ALERT_DRIVER_UNLOADED_FAST = 3,
    ALERT_DRIVER_LOADED_CALLBACKS_DEAD = 4,
    ALERT_CANARY_PEER_DEAD = 5,
    ALERT_QUORUM_LOST = 6,
} CanaryMesh_ALERT_TYPE;

typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY      InLoadOrderLinks;
    PVOID           ExceptionTable;
    ULONG           ExceptionTableSize;
    PVOID           GpValue;
    PVOID           NonPagedDebugInfo;
    PVOID           DllBase;
    PVOID           EntryPoint;
    ULONG           SizeOfImage;
    UNICODE_STRING  FullDllName;
    UNICODE_STRING  BaseDllName;
    ULONG           Flags;
    USHORT          LoadCount;
    USHORT          TlsIndex;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

typedef struct _CANARY_IDENTITY {
    ULONG           CanaryId;
    WCHAR           ServiceName[64];
    PVOID           DriverObjectAddress;
    PVOID           AlertEntryPoint;
    LARGE_INTEGER   RegistrationTime;
    ULONG           RegistrationPid;
    volatile LONG   Status;
    volatile LONG64 LastHeartbeatTime;
    volatile LONG   HeartbeatSequence;
} CANARY_IDENTITY, * PCANARY_IDENTITY;

typedef struct _CanaryMesh_EDR_CALLBACK_BASELINE {
    // DetectorOne publishes the callback entry points it expects to stay
    // registered in the kernel notification arrays.
    PVOID               ProcessCallbackAddress;
    PVOID               ImageCallbackAddress;
    PVOID               ThreadCallbackAddress;
    volatile LONG64* ProcessEventCounter;
    volatile LONG64* ImageEventCounter;
    LONG64              BaselineProcessCount;
    LONG64              BaselineImageCount;
    LARGE_INTEGER       BaselineCaptureTime;
    BOOLEAN             Valid;
} CanaryMesh_EDR_CALLBACK_BASELINE, * PCanaryMesh_EDR_CALLBACK_BASELINE;

typedef struct _CanaryMesh_CANARY_TABLE {
    // DetectorOne allocates this table and shares it with all canaries.
    // Volatile fields are updated through interlocked operations because
    // multiple driver instances can vote and refresh liveness concurrently.
    ULONG               Magic;
    ULONG               Version;
    volatile LONG       RegisteredCount;
    volatile LONG       AliveCount;
    ULONG               ExpectedCount;
    volatile LONG       HandoffComplete;
    ULONG               QuorumRequired;
    volatile LONG       AlertGeneration;
    volatile LONG       AlertVotes;
    volatile LONG       AlertActive;
    volatile LONG       AlertVoteBitmap;
    volatile LONG       ConsensusEmitted;
    WCHAR               SuspectDriverName[260];
    LARGE_INTEGER       SuspectDriverLoadTime;
    ULONG               SuspectDriverRiskScore;
    volatile LONG       AlertDispatched;
    CANARY_IDENTITY     Canaries[CanaryMesh_MAX_CANARIES];
    CanaryMesh_EDR_CALLBACK_BASELINE CallbackBaseline;
    volatile LONG       SuspectDriverStillLoaded;
    WCHAR               SuspectDriverTracked[260];
    volatile LONG       ShutdownPending;
} CanaryMesh_CANARY_TABLE, * PCanaryMesh_CANARY_TABLE;

typedef struct _CANARY_ALERT_CONTEXT {
    // Per-canary copy of the current suspicious-driver incident. This keeps
    // local signal state separate from the shared quorum table.
    volatile LONG       Active;
    WCHAR               DriverName[260];
    LARGE_INTEGER       LoadTimestamp;
    ULONG               RiskScore;
    LARGE_INTEGER       ActivationTime;
    volatile LONG       DriverStillLoaded;
    volatile LONG       UnloadDetected;
    LARGE_INTEGER       UnloadTimestamp;
    volatile LONG       CallbackRemovalDetected;
    volatile LONG       LivenessDropDetected;
    LARGE_INTEGER       CallbackLossTimestamp;
    volatile LONG       DetectedSignals;
} CANARY_ALERT_CONTEXT, * PCANARY_ALERT_CONTEXT;

typedef struct _EX_CALLBACK_ROUTINE_BLOCK {
    // Internal callback table entries may point at EX_CALLBACK_ROUTINE_BLOCK
    // records rather than directly at the registered function pointer.
    EX_RUNDOWN_REF  RundownProtect;
    PVOID           Function;
    PVOID           Context;
} EX_CALLBACK_ROUTINE_BLOCK, * PEX_CALLBACK_ROUTINE_BLOCK;

typedef struct _CANARY_GLOBAL_STATE {
    // Process-wide canary state. Only DriverEntry defines this object; other
    // translation units access it through the extern declaration below.
    ULONG                       CanaryId;
    PCanaryMesh_CANARY_TABLE    Table;
    PETHREAD                    HeartbeatThread;
    PETHREAD                    DriverWatchThread;
    PETHREAD                    CallbackWatchThread;
    volatile LONG               ShouldStop;
    CANARY_ALERT_CONTEXT        Alert;
    KEVENT                      AlertEvent;
    FAST_MUTEX                  AlertLock;
    BOOLEAN                     SignalAProcessBaselineValid;
    BOOLEAN                     SignalAImageBaselineValid;
    BOOLEAN                     SignalAThreadBaselineValid;
    BOOLEAN                     LivenessObservedAfterAlert;
    LONG64                      LivenessProcessBaseline;
    LONG64                      LivenessImageBaseline;
    LARGE_INTEGER               LivenessBaselineCaptureTime;
    LARGE_INTEGER               LastConsensusReportTime;
} CANARY_GLOBAL_STATE;

extern CANARY_GLOBAL_STATE g_State;
extern PVOID g_ProcessCallbackTableAddress;
extern PVOID g_ImageCallbackTableAddress;
extern PVOID g_ThreadCallbackTableAddress;
extern volatile LONG HasVotedThisRound;

// ============================================================
// Forward declarations
// ============================================================

DRIVER_UNLOAD   CanaryUnload;
VOID            CanaryHeartbeatThread(PVOID Context);
VOID            CanaryDriverWatchThread(PVOID Context);
VOID            CanaryCallbackWatchThread(PVOID Context);
VOID            CanaryWatchdogThread(PVOID Context);
VOID            CanaryCastVote(IN CanaryMesh_ALERT_TYPE AlertType);
VOID            CanaryEmitConsensusAlert(IN CanaryMesh_ALERT_TYPE AlertType, IN LONG Votes);
VOID            CanaryMaybeEmitPeriodicConsensus(IN CanaryMesh_ALERT_TYPE AlertType);
VOID            CanaryLogState(IN PCSTR Context);

NTSTATUS        CanaryRegisterWithDetectorOne(IN PDRIVER_OBJECT DriverObject);
NTSTATUS        CanaryWaitForHandoff(IN PCanaryMesh_CANARY_TABLE Table);
PVOID           CanaryFindCallbackTableForRoutine(IN PCWSTR RoutineName, IN PVOID TargetCallback);
PVOID           CanaryFindCallbackTableInCode(IN PUCHAR FunctionAddress, IN PCWSTR RoutineName, IN PVOID TargetCallback, IN ULONG Depth);

BOOLEAN         CanaryIsLivenessCounterFrozen();
BOOLEAN         CanaryIsSuspectDriverLoaded(IN PWSTR DriverName);
BOOLEAN         CanaryIsLowestAliveCanary();
BOOLEAN         CanaryVerifyCallbackPointerInTable(IN PVOID TargetCallback);
BOOLEAN         CanaryVerifyCallbackPointerForRoutine(IN PCWSTR RoutineName, IN PVOID TargetCallback, IN OUT PVOID* CachedTable);
BOOLEAN         CanaryCallbackTableContains(IN PVOID TableAddress, IN PVOID TargetCallback, IN BOOLEAN Verbose);

extern "C" VOID NTAPI CanaryReceiveAlert(
    IN PWSTR            DriverName,
    IN PLARGE_INTEGER   LoadTimestamp,
    IN ULONG            RiskScore
);

extern "C" LIST_ENTRY   PsLoadedModuleList;
extern "C" PERESOURCE   PsLoadedModuleResource;

