#pragma once

#include <ntifs.h>
#include <intrin.h>
#include <wdm.h>
#include <ntddk.h>
#include <ntimage.h>
#include <ntstrsafe.h>

// Core policy and sizing constants used by the DetectorOne sensor.
#define POOL_TAG                        'PooT'
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#define PROCESS_QUERY_INFORMATION        0x0400
#define SNAPSHOT_SIZE                    512
#define DetectorOne_MAX_CANARIES              5
#define DetectorOne_CANARY_LOAD_TIMEOUT_MS    15000
#define DetectorOne_HIGH_RISK_THRESHOLD       100

#define KRATOS_MAX_SERVICE_ENTRIES  32
#define KRATOS_SERVICE_NAME_MAX     128
#define KRATOS_IMAGE_PATH_MAX       260
#define DETECTORONE_EVENT_RING_SIZE 4096
#define DETECTORONE_MAX_EVENTS_PER_BATCH 256
#define DETECTORONE_EVENT_TEXT_MAX 260

// Thread callbacks are high-volume on a live system. Keep the kernel-side
// inventory enabled, but do not stream every thread transition to user mode
// until the engine has filtering/backpressure.
#define DETECTORONE_STREAM_THREAD_EVENTS 0

// Kernel device exposed to CanaryMesh for IOCTL registration.
#define DETECTOR_DEVICE_NAME      L"\\Device\\KratosEDR"
#define DETECTOR_SYMLINK_NAME     L"\\DosDevices\\KratosEDR"


// IOCTL contract shared with CanaryMesh. Keep request/response layouts
// synchronized across both projects before changing these codes.
#define IOCTL_KRATOS_REGISTER   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, \
                                    METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KRATOS_GET_TABLE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, \
                                    METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KRATOS_TEST_SIGNAL_A CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, \
                                    METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KRATOS_GET_EVENTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, \
                                    METHOD_BUFFERED, FILE_ANY_ACCESS)

DECLARE_CONST_UNICODE_STRING(servicesKeyPrefix, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");

extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(
    _In_  PEPROCESS SourceProcess,
    _In_  PVOID     SourceAddress,
    _In_  PEPROCESS TargetProcess,
    _Out_ PVOID     TargetAddress,
    _In_  SIZE_T    BufferSize,
    _In_  KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T   ReturnSize
);

extern "C" UCHAR* NTAPI PsGetProcessImageFileName(_In_ PEPROCESS Process);

extern "C" NTSTATUS NTAPI ZwOpenThread(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ PCLIENT_ID ClientId
);

extern "C" NTSTATUS NTAPI ZwQueryInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
);

typedef struct _DETECTORONE_IAT_CAPABILITIES DETECTORONE_IAT_CAPABILITIES; // Forward declaration

// Process and thread inventory records maintained from PsSet* callbacks.
typedef struct _PROCESS_ENTRY {
    LIST_ENTRY      ProcessListEntry;
    HANDLE          ProcessId;
    HANDLE          ParentProcessId;
    UNICODE_STRING  ImageFileName;
    LARGE_INTEGER   CreateTime;
} PROCESS_ENTRY, * PPROCESS_ENTRY;

typedef struct _THREAD_ENTRY {
    LIST_ENTRY      ThreadListEntry;
    HANDLE          ProcessId;
    HANDLE          ThreadId;
    LARGE_INTEGER   CreateTime;
} THREAD_ENTRY, * PTHREAD_ENTRY;

// Snapshot of a user-mode RWX memory region used for later comparison.
typedef struct _RWX_REGION_ENTRY {
    RTL_BALANCED_LINKS  Links;
    HANDLE              ProcessId;
    PVOID               BaseAddress;
    SIZE_T              RegionSize;
    UCHAR               ContentSnapShot[SNAPSHOT_SIZE];
    SIZE_T              SnapshotActualSize;
} RWX_REGION_ENTRY, * PRWX_REGION_ENTRY;


// Raw IAT score buckets. Each dangerous import contributes to one or more
// buckets, then combination logic turns these buckets into final risk.
typedef struct _DETECTORONE_IAT_SCORE {
    ULONG   MemoryAccess;
    ULONG   ProcessInteraction;
    ULONG   KernelManipulation;
    ULONG   CallbackInteraction;
    ULONG   DangerousTotal;
    BOOLEAN ImportsZwTerminateProcess;
    BOOLEAN ImportsMmMapIoSpace;
    BOOLEAN ImportsMmGetPhysicalAddress;
    BOOLEAN ImportsZwMapViewOfSection;
} DETECTORONE_IAT_SCORE, * PDETECTORONE_IAT_SCORE;

// High-level capabilities inferred from imports. Policy decisions should use
// these flags instead of matching only one API name when possible.
typedef struct _DETECTORONE_IAT_CAPABILITIES {
    BOOLEAN HasProcessEnum;
    BOOLEAN HasProcessOpen;
    BOOLEAN HasProcessTerminate;
    BOOLEAN HasMemoryAccess;
    BOOLEAN HasCallbackRemoval;
    BOOLEAN HasMsrAccess;
} DETECTORONE_IAT_CAPABILITIES, * PDETECTORONE_IAT_CAPABILITIES;

// Weighted import rule used by DetectorOneScoreImport.
typedef struct _DETECTORONE_DANGEROUS_IMPORT {
    PCSTR   FunctionName;
    ULONG   Weight;
    PCSTR   Category;
} DETECTORONE_DANGEROUS_IMPORT, * PDETECTORONE_DANGEROUS_IMPORT;


// Canary lifecycle state stored in the shared mesh table.
typedef enum _CANARY_STATUS {
    CANARY_STATUS_UNKNOWN = 0,
    CANARY_STATUS_ALIVE = 1,
    CANARY_STATUS_SUSPECTED = 2,
    CANARY_STATUS_DEAD = 3
} CANARY_STATUS;

// Per-canary identity and heartbeat record. Written by DetectorOne during
// registration and refreshed by canary heartbeat threads.
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

// Baseline exported to canaries. Signal A verifies these callback addresses
// remain present; Signal B checks that event counters continue moving.
typedef struct _DetectorOne_EDR_CALLBACK_BASELINE {
    PVOID               ProcessCallbackAddress;
    PVOID               ImageCallbackAddress;
    PVOID               ThreadCallbackAddress;
    volatile LONG64* ProcessEventCounter;
    volatile LONG64* ImageEventCounter;
    LONG64              BaselineProcessCount;
    LONG64              BaselineImageCount;
    LARGE_INTEGER       BaselineCaptureTime;
    BOOLEAN             Valid;
} DetectorOne_EDR_CALLBACK_BASELINE, * PDetectorOne_EDR_CALLBACK_BASELINE;

// Shared nonpaged coordination table between DetectorOne and CanaryMesh.
// This table is intentionally stable and guarded by layout assertions below.
typedef struct _DetectorOne_CANARY_TABLE {
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
    CANARY_IDENTITY     Canaries[DetectorOne_MAX_CANARIES];
    DetectorOne_EDR_CALLBACK_BASELINE CallbackBaseline;
    volatile LONG   SuspectDriverStillLoaded;
    WCHAR           SuspectDriverTracked[260];

    volatile LONG IsUnloading; // 0 = normal, 1 = global unload requested
    volatile LONG RegisteredCanaryCount;
    volatile LONG       ShutdownPending; // 1 = DetectorOne is unloading; canaries must stop
} DetectorOne_CANARY_TABLE, * PDetectorOne_CANARY_TABLE;

// Type of the CanaryReceiveAlert function exported by each canary
typedef VOID(NTAPI* FN_CanaryReceiveAlert)(
    IN PWSTR            DriverName,
    IN PLARGE_INTEGER   LoadTimestamp,
    IN ULONG            RiskScore
    );

#pragma pack(push, 8)  // Keep explicit 8-byte alignment for cross-driver IOCTL ABI.
typedef struct _KRATOS_REGISTER_REQUEST {
    ULONG   CanaryId;
    ULONG   _pad;              // Explicit padding to align pointer fields
    PVOID   DriverObjectAddress;
    PVOID   AlertEntryPoint;
} KRATOS_REGISTER_REQUEST, * PKRATOS_REGISTER_REQUEST;

typedef struct _KRATOS_REGISTER_RESPONSE {
    NTSTATUS    Status;
    ULONG       _pad;          // Explicit padding keeps response layout stable
    PVOID       TablePointer;
    PVOID       ProcessCallbackAddress;
    PVOID       ImageCallbackAddress;
    PVOID       ThreadCallbackAddress;
    PVOID       ProcessEventCounterPtr;
    PVOID       ImageEventCounterPtr;
} KRATOS_REGISTER_RESPONSE, * PKRATOS_REGISTER_RESPONSE;
#pragma pack(pop)

typedef VOID(NTAPI* FN_CanaryReceiveAlert)(
    IN PWSTR            DriverName,
    IN PLARGE_INTEGER   LoadTimestamp,
    IN ULONG            RiskScore
);

typedef enum _BYOVD_PRIMITIVE_CATEGORY {
    PRIMITIVE_UNKNOWN = 0,
    PRIMITIVE_PHYSICAL_MEMORY = 1,  // MmMapIoSpace, MmGetPhysicalAddress
    PRIMITIVE_MSR_PORT_IO = 2,  // __readmsr, __writemsr, port I/O
    PRIMITIVE_DRIVER_KILLER = 3,  // ZwTerminateProcess-focused EDR killer
    PRIMITIVE_ARBITRARY_RW = 4,  // ZwMapViewOfSection + R/W
    PRIMITIVE_COMBO = 5,  // Multiple dangerous capability categories
} BYOVD_PRIMITIVE_CATEGORY;

typedef struct _KRATOS_SERVICE_ENTRY {
    BOOLEAN     Valid;
    BOOLEAN     Blocked;
    WCHAR       ServiceName[KRATOS_SERVICE_NAME_MAX];   // "k7rkscan"
    WCHAR       ServicePath[KRATOS_SERVICE_NAME_MAX];   // full registry service path
    WCHAR       ImagePath[KRATOS_IMAGE_PATH_MAX];       // driver .sys path
    LARGE_INTEGER RegisterTime;
} KRATOS_SERVICE_ENTRY, * PKRATOS_SERVICE_ENTRY;


// Canary health snapshot captured by DetectorOne to detect mesh anomalies.
typedef struct _KRATOS_CANARY_HEALTH_SNAPSHOT {
    ULONG           CanaryId;
    LONG64          LastHeartbeatTime;
    LONG            HeartbeatSequence;
    CANARY_STATUS   Status;
    BOOLEAN         PresentInModuleList;  // Still loaded in kernel module list
} KRATOS_CANARY_HEALTH_SNAPSHOT, * PKRATOS_CANARY_HEALTH_SNAPSHOT;


// DetectorOne-side canary health monitor state.
typedef struct _KRATOS_CANARY_MONITOR_STATE {
    KRATOS_CANARY_HEALTH_SNAPSHOT Baseline[DetectorOne_MAX_CANARIES];
    LARGE_INTEGER                 BaselineCaptureTime;
    LARGE_INTEGER                 AlertGracePeriodEnd; // post-alert grace period end
    volatile LONG                 AlertPhaseActive;    // 1 = suspect driver is loaded
    volatile LONG                 CanaryKillDetected;  // 1 = strong canary-loss signal
    PETHREAD                      MonitorThread;
    volatile LONG                 ShouldStop;
} KRATOS_CANARY_MONITOR_STATE, * PKRATOS_CANARY_MONITOR_STATE;


// Structured events consumed by DetectorOneEngine through IOCTL_KRATOS_GET_EVENTS.
typedef enum _DETECTORONE_EVENT_TYPE {
    DETECTORONE_EVENT_PROCESS_CREATE = 1,
    DETECTORONE_EVENT_PROCESS_EXIT = 2,
    DETECTORONE_EVENT_THREAD_CREATE = 3,
    DETECTORONE_EVENT_THREAD_EXIT = 4,
    DETECTORONE_EVENT_IMAGE_LOAD = 5,
    DETECTORONE_EVENT_DRIVER_BLOCKED = 6,
    DETECTORONE_EVENT_CANARY_ALERT = 7,
    DETECTORONE_EVENT_PROCESS_TERMINATE = 8,
    DETECTORONE_EVENT_RWX_THREAD_START = 9,
    DETECTORONE_EVENT_RWX_REGION = 10,
    DETECTORONE_EVENT_REGISTRY_SERVICE = 11
} DETECTORONE_EVENT_TYPE;

typedef struct _DETECTORONE_TELEMETRY_EVENT {
    ULONG Size;
    ULONG Type;
    ULONG64 Sequence;
    LARGE_INTEGER Timestamp;
    ULONG64 ProcessId;
    ULONG64 ParentProcessId;
    ULONG64 ThreadId;
    ULONG64 Address;
    ULONG64 RegionSize;
    ULONG Protection;
    ULONG RiskScore;
    ULONG Flags;
    WCHAR ImagePath[DETECTORONE_EVENT_TEXT_MAX];
    WCHAR Detail[64];
} DETECTORONE_TELEMETRY_EVENT, *PDETECTORONE_TELEMETRY_EVENT;

typedef struct _DETECTORONE_EVENT_BATCH {
    ULONG Version;
    ULONG Count;
    ULONG DroppedEvents;
    ULONG Reserved;
    DETECTORONE_TELEMETRY_EVENT Events[DETECTORONE_MAX_EVENTS_PER_BATCH];
} DETECTORONE_EVENT_BATCH, *PDETECTORONE_EVENT_BATCH;

typedef enum _KRATOS_IMMEDIATE_ALERT_TYPE {
    ALERT_PREEMPTIVE_CANARY_KILL = 100,  // attacker targets canaries first
    ALERT_CANARY_COUNT_CRITICAL = 101,  // not enough canaries for quorum
} KRATOS_IMMEDIATE_ALERT_TYPE;

typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    ULONG ExceptionTableSize;
    PVOID GpValue;
    PVOID NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT SignatureLevel : 4;
    USHORT SignatureType : 3;
    USHORT Unused : 9;
    PVOID SectionPointer;
    ULONG CheckSum;
    ULONG CoverageSectionSize;
    PVOID CoverageSection;
    PVOID LoadedImports;
    PVOID Spare;
    ULONG SizeOfImageNotRounded;
    ULONG TimeDateStamp;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

// Compile-time ABI checks for structures shared with CanaryMesh.
C_ASSERT(sizeof(KRATOS_REGISTER_REQUEST) == 24);
C_ASSERT(sizeof(KRATOS_REGISTER_RESPONSE) == 56);
C_ASSERT(FIELD_OFFSET(KRATOS_REGISTER_REQUEST, AlertEntryPoint) == 16);
C_ASSERT(FIELD_OFFSET(KRATOS_REGISTER_RESPONSE, ProcessCallbackAddress) == 16);

// Global driver state. DriverEntry.cpp owns the storage; other modules use extern declarations.
extern PDEVICE_OBJECT   g_DeviceObject;
extern BOOLEAN          g_SymlinkCreated;
extern const DETECTORONE_DANGEROUS_IMPORT g_DangerousImports[];


extern RTL_AVL_TABLE    g_RwxTable;
extern LIST_ENTRY       g_ProcessList;
extern LIST_ENTRY       g_ThreadList;
extern FAST_MUTEX       g_ProcessListLock;
extern FAST_MUTEX       g_ThreadListLock;
extern FAST_MUTEX       g_RwxTableLock;


extern BOOLEAN          g_ProcessCallbackRegistered;
extern BOOLEAN          g_ThreadCallbackRegistered;
extern BOOLEAN          g_ImageLoadCallbackRegistered;
extern BOOLEAN          g_RegistryCallbackRegistered;
extern volatile LONG    g_Unloading;
extern LARGE_INTEGER    g_RegistryCallbackCookie;

// Liveness counters, incremented with each callback
// Exported to canaries via DetectorOneGetLivenessCounters()
// Allows detection of whether callbacks are still being invoked
extern volatile LONG64  g_ProcessEventCounter;
extern volatile LONG64  g_ImageEventCounter;
extern volatile LONG    g_AlertDispatching;
extern volatile LONG    HasVotedThisRound;
// Shared canary mesh table allocated during bootstrap.
extern PDetectorOne_CANARY_TABLE g_CanaryTable;

extern KRATOS_SERVICE_ENTRY g_ServiceTable[KRATOS_MAX_SERVICE_ENTRIES];
extern KRATOS_CANARY_MONITOR_STATE g_CanaryMonitor;
extern FAST_MUTEX            g_ServiceTableLock;
extern ULONG                 g_ServiceTableIndex;
extern FAST_MUTEX            g_TelemetryLock;
extern DETECTORONE_TELEMETRY_EVENT g_TelemetryRing[DETECTORONE_EVENT_RING_SIZE];
extern ULONG                 g_TelemetryHead;
extern ULONG                 g_TelemetryCount;
extern ULONG                 g_TelemetryDropped;
extern volatile LONG64       g_TelemetrySequence;


// Canary service registry paths loaded by DetectorOne during bootstrap.
extern const WCHAR* g_CanaryServicePaths[];
extern const ULONG g_CanaryCount;


#ifdef __cplusplus
extern "C" {
#endif
    extern LIST_ENTRY PsLoadedModuleList;
    extern ERESOURCE PsLoadedModuleResource;

#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
extern "C" {
#endif

VOID        DetectorOneCreateProcessNotify(PEPROCESS, HANDLE, PPS_CREATE_NOTIFY_INFO);
VOID        DetectorOneCreateThreadNotify(HANDLE, HANDLE, BOOLEAN);
VOID        DetectorOneLoadImageNotify(PUNICODE_STRING, HANDLE, PIMAGE_INFO);
VOID        KratosStoreServiceEntry( IN PCUNICODE_STRING KeyName, IN PCWSTR ImagePathValue, IN BOOLEAN  Blocked );
VOID        DetectorOneCaptureRWXSnapshot(PEPROCESS, PVOID, PRWX_REGION_ENTRY);
VOID        DetectorOneUnloadDriver(PDRIVER_OBJECT);
    VOID        DetectorOneLogRegistryServiceEvent(IN PCSTR Operation, IN PCUNICODE_STRING KeyName, IN PCUNICODE_STRING ValueName, IN ULONG Type, IN ULONG DataSize);
VOID        DetectorOneScoreImport(IN PCSTR FunctionName, IN PCSTR DllName, IN OUT PDETECTORONE_IAT_SCORE Score, IN OUT PDETECTORONE_IAT_CAPABILITIES Caps);
VOID        DetectorOneHandoffToCanaries();
VOID        DetectorOneDispatchAlertToCanaries(IN PUNICODE_STRING DriverName, IN PLARGE_INTEGER LoadTimestamp, IN ULONG RiskScore);
VOID        KratosDispatchAlertToCanaries(IN PUNICODE_STRING  DriverName,IN PLARGE_INTEGER LoadTimestamp,IN ULONG RiskScore);
VOID        KratosHandleHighRiskDriver(IN PUNICODE_STRING FullImageName, IN PDETECTORONE_IAT_SCORE   IatScore, IN PDETECTORONE_IAT_CAPABILITIES Caps, IN ULONG TotalRiskScore);
VOID        KratosSnapshotCanaryBaseline();
VOID        KratosCanaryMonitorThread(PVOID Context);
VOID        KratosRaiseImmediateAlert(IN KRATOS_IMMEDIATE_ALERT_TYPE  AlertType, IN ULONG AliveCount, IN ULONG  ExpectedCount);
    VOID        DetectorOneQueueTelemetryEvent(IN DETECTORONE_EVENT_TYPE Type, IN ULONG64 ProcessId, IN ULONG64 ParentProcessId, IN ULONG64 ThreadId, IN PCUNICODE_STRING ImagePath, IN PCWSTR Detail, IN ULONG RiskScore, IN ULONG Flags);
    VOID        DetectorOneQueueTelemetryEventEx(IN DETECTORONE_EVENT_TYPE Type, IN ULONG64 ProcessId, IN ULONG64 ParentProcessId, IN ULONG64 ThreadId, IN ULONG64 Address, IN ULONG64 RegionSize, IN ULONG Protection, IN PCUNICODE_STRING ImagePath, IN PCWSTR Detail, IN ULONG RiskScore, IN ULONG Flags);
ULONG       DetectorOneDrainTelemetryEvents(OUT PDETECTORONE_EVENT_BATCH Batch, IN ULONG OutputLength);

NTSTATUS    DetectorOneTestSignalA();
NTSTATUS    DetectorOneRegistryCallback(PVOID, PVOID, PVOID);
NTSTATUS    DetectorOneAnalyzeDriverIAT(IN PVOID ImageBase, IN SIZE_T ImageSize, OUT PDETECTORONE_IAT_SCORE Score, OUT PULONG TotalRiskScore, OUT PDETECTORONE_IAT_CAPABILITIES   OutCaps);
NTSTATUS    DetectorOneAnalyzeDriverIATFromFile(IN PVOID FileBase, IN SIZE_T FileSize, OUT PDETECTORONE_IAT_SCORE Score, OUT PULONG TotalRiskScore, OUT PDETECTORONE_IAT_CAPABILITIES OutCaps);
NTSTATUS    DetectorOneBootstrapCanaries();
NTSTATUS    DetectorOneWaitForCanaryRegistrations(IN ULONG TimeoutMs);
NTSTATUS    DetectorOneDispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS    DetectorOneDispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS    KratosForceUnloadDriver(IN PUNICODE_STRING DriverImagePath);
//NTSTATUS    KratosFindServicePath(_In_ PCUNICODE_STRING DriverImagePath, _Out_ PUNICODE_STRING ServiceRegistryPath);
NTSTATUS    KratosFindServicePath(IN  PUNICODE_STRING DriverImagePath, OUT PUNICODE_STRING ServicePath);
//NTSTATUS    KratosEnableLoadDriverPrivilege(OUT PBOOLEAN WasEnabled);
NTSTATUS    KratosReadAndAnalyzeDriverOnDisk(IN  PCWSTR ImagePathValue, OUT PULONG  RiskScore, OUT PDETECTORONE_IAT_SCORE  IatScore, OUT PDETECTORONE_IAT_CAPABILITIES IatCaps);
NTSTATUS    NTAPI DetectorOneRegisterCanary(IN ULONG CanaryId, IN PVOID DriverObjectAddress, IN PVOID  AlertEntryPoint);

BOOLEAN     DetectorOneIsImageRangeValid(IN SIZE_T ImageSize, IN ULONG Rva, IN SIZE_T Length);
BOOLEAN     DetectorOneIsSysDriverName(IN PUNICODE_STRING FullImageName);
BOOLEAN     DetectorOneIsDriverFromSystem32Drivers(IN PUNICODE_STRING Name);
BOOLEAN     DetectorOneUnicodeContainsInsensitive(IN PCUNICODE_STRING Text, IN PCWSTR Pattern);
BOOLEAN     DetectorOneUnicodeEqualsInsensitive(IN PCUNICODE_STRING Text, IN PCWSTR Pattern);
BOOLEAN     BaseNamesMatch(IN PCWSTR Name1, IN PCWSTR Name2);
BOOLEAN     KratosIsCanaryStillLoaded(IN ULONG CanaryId);

INT         DetectorOneAsciiCompareInsensitive(IN PCSTR First, IN PCSTR Second);

ULONG       DetectorOneDetectDangerousCombinations(IN PDETECTORONE_IAT_CAPABILITIES Caps, IN PDETECTORONE_IAT_SCORE Score);
ULONG       DetectorOneCalculateQuorum(IN ULONG TotalCanaries);

BYOVD_PRIMITIVE_CATEGORY KratosClassifyPrimitive(IN PDETECTORONE_IAT_SCORE Score,IN PDETECTORONE_IAT_CAPABILITIES Caps);

PCWSTR      ExtractBaseName(IN PCWSTR FullPath);

#ifdef __cplusplus
}
#endif


