# DetectorOne

DetectorOne is an experimental Windows kernel-mode EDR sensor focused on defensive detection of BYOVD-style activity. It monitors driver load paths, inspects kernel driver imports, classifies risky primitives, and coordinates a canary mesh that watches for attempts to blind or disable the sensor.

> Status: research prototype. Use only in an isolated Windows kernel debugging lab.

## What It Does

DetectorOne operates as the primary kernel sensor. Its main responsibilities are:

- register process, thread, image-load, and registry callbacks;
- detect kernel-mode `.sys` image loads;
- parse driver PE import tables and score suspicious kernel APIs;
- block selected risky drivers before load by denying service `ImagePath` writes;
- dispatch high-risk driver alerts to CanaryMesh;
- export callback baselines and liveness counters to canaries;
- track canary health and quorum state.

The project is defensive by design. It does not provide exploit primitives, arbitrary kernel read/write helpers, or tooling for loading vulnerable drivers.

## Architecture

```text
DetectorOne.sys
|
+-- DriverEntry.cpp
|   +-- driver bootstrap
|   +-- device/IOCTL surface
|   +-- callback registration
|   +-- ordered unload
|
+-- DetectorOneCallbacks.inl
|   +-- process/thread/image callbacks
|   +-- driver load detection
|   +-- registry pre-load enforcement
|   +-- IOCTL dispatch
|
+-- DetectorOneIatRegistry.inl
|   +-- PE/IAT parser
|   +-- BYOVD import scoring
|   +-- primitive classification
|   +-- service path tracking
|
+-- DetectorOneCanaries.inl
|   +-- canary bootstrap
|   +-- canary registration
|   +-- alert dispatch
|   +-- health monitoring
|
+-- header.h
    +-- shared ABI structures
    +-- policy constants
    +-- global sensor state
    +-- subsystem prototypes
```

The implementation blocks are included as `.inl` files instead of separate compiled `.cpp` units because `header.h` currently owns `static` global state. Keeping a single translation unit preserves one shared DetectorOne state instance across all subsystems.

## Detection Model

DetectorOne uses two complementary detection paths.

### Pre-Load Registry Enforcement

The registry callback watches service `ImagePath` writes under:

```text
\Registry\Machine\System\CurrentControlSet\Services\
```

When a driver service path is written, DetectorOne attempts to resolve and read the `.sys` file before it is loaded. The file is parsed as PE64 and its IAT is scored. If policy decides the driver should not load, the registry callback returns an error and the `ImagePath` write is denied.

Current examples:

- pure `ZwTerminateProcess` process-killer category can be blocked early;
- critical aggregate IAT score can be blocked;
- dangerous capability combinations can be blocked.

### Post-Load Image Notification

The image-load callback inspects kernel-mode `.sys` images after Windows reports the load. DetectorOne scores the loaded image and, for high-risk findings, updates the shared canary table and dispatches an alert to registered canaries.

High-risk conditions include:

- `ZwTerminateProcess`;
- `MmMapIoSpace`;
- `MmGetPhysicalAddress` combined with `ZwMapViewOfSection`;
- aggregate risk score greater than or equal to `DetectorOne_HIGH_RISK_THRESHOLD`.

## IAT Scoring

Suspicious imports are defined in `g_DangerousImports` in `header.h`. Each import maps to a category and weight.

Primary categories:

- `PROCESS_KILL`
- `PROCESS_ACCESS`
- `PROCESS_ENUM`
- `PHYSICAL_MEMORY`
- `MEMORY_MAPPING`
- `CALLBACK_MANIP`
- `CALLBACK_REMOVAL`
- `MSR_ACCESS`

DetectorOne does not rely only on a single API name. It converts imports into capability flags such as:

- process enumeration/open/terminate;
- memory access and mapping;
- callback manipulation/removal;
- MSR or port I/O access.

Combination scoring then raises severity when imports form a BYOVD-style kill chain, such as process access plus termination, physical memory plus termination, or callback removal plus termination.

## Canary Mesh Integration

DetectorOne creates `\Device\KratosEDR` and exposes an IOCTL contract used by CanaryMesh.

Important IOCTLs:

- `IOCTL_KRATOS_REGISTER`
- `IOCTL_KRATOS_GET_TABLE`
- `IOCTL_KRATOS_TEST_SIGNAL_A`

During bootstrap, DetectorOne loads configured canary services and waits for registration. Registered canaries receive:

- pointer to the shared canary table;
- DetectorOne process/image/thread callback addresses;
- liveness counter pointers;
- alert entry point dispatch support.

Canaries use this baseline to detect:

- callback pointer removal;
- frozen callback liveness;
- suspect driver unload patterns;
- canary peer loss or quorum degradation.

## Shared ABI

The following structures are part of the cross-driver ABI and must remain synchronized with CanaryMesh:

- `KRATOS_REGISTER_REQUEST`
- `KRATOS_REGISTER_RESPONSE`
- `DetectorOne_CANARY_TABLE`
- `DetectorOne_EDR_CALLBACK_BASELINE`
- `CANARY_IDENTITY`

The project uses compile-time layout checks:

```cpp
C_ASSERT(sizeof(KRATOS_REGISTER_REQUEST) == 24);
C_ASSERT(sizeof(KRATOS_REGISTER_RESPONSE) == 56);
C_ASSERT(FIELD_OFFSET(KRATOS_REGISTER_REQUEST, AlertEntryPoint) == 16);
C_ASSERT(FIELD_OFFSET(KRATOS_REGISTER_RESPONSE, ProcessCallbackAddress) == 16);
```

Any ABI change should be made in DetectorOne and CanaryMesh together.

## Build Requirements

Recommended lab environment:

- Windows 10/11 test VM;
- Visual Studio 2022;
- Windows Driver Kit 10;
- test-signing enabled in the lab VM;
- kernel debugging configured;
- CanaryMesh built and installed if canary integration is being tested.

Build command:

```powershell
& 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe' `
  'C:\Users\ultim\source\repos\DectectorOne\DectectorOne.sln' `
  /p:Configuration=Debug `
  /p:Platform=x64 `
  /m
```

Expected output:

```text
C:\Users\ultim\source\repos\DectectorOne\x64\Debug\DectectorOne.sys
```

Note: on the current workstation, MSBuild completes compilation, link, signing, and packaging, but reports an environment issue for `InfVerif.dll`. `inf2cat` still reports no signability errors.

## Deployment Notes

This driver should be deployed only in a controlled kernel lab. Before loading:

- enable test signing if using test certificates;
- use a VM snapshot;
- attach a kernel debugger;
- ensure CanaryMesh service names match `g_CanaryServicePaths`;
- verify the vulnerable-driver blocklist and platform security settings expected for the test.

Example lab commands vary by signing and install method. Keep installation scripts out of production hosts.

## Logging

DetectorOne logs through `DbgPrint`. Typical log sources:

- driver bootstrap and unload;
- callback registration failures;
- registry service `ImagePath` writes;
- pre-load IAT analysis;
- post-load driver scoring;
- high-risk BYOVD classification;
- canary registration and alert dispatch;
- canary health anomalies.

Use DebugView, WinDbg, or kernel debugger output capture in the lab VM.

## Repository Layout

```text
DectectorOne.sln
DectectorOne/
  DectectorOne.vcxproj
  DectectorOne.inf
  DriverEntry.cpp
  DetectorOneCallbacks.inl
  DetectorOneIatRegistry.inl
  DetectorOneCanaries.inl
  header.h
  log.cpp
  log.h
```

## Engineering Notes

- Keep cross-driver ABI structures packed and asserted.
- Avoid moving `.inl` blocks into separate `.cpp` files until `header.h` globals are converted from `static` definitions to `extern` declarations with one owning `.cpp`.
- Keep registry pre-load enforcement conservative. A false positive at this stage prevents driver service configuration.
- Treat IAT analysis as a heuristic, not proof of malicious behavior.
- Keep canary alert dispatch isolated with exception handling so one failed canary does not break the mesh.

## Safety Scope

DetectorOne is intended for defensive research, telemetry validation, and BYOVD detection engineering. Do not use it to bypass operating system protections or to load, exploit, or weaponize vulnerable drivers.
