# DetectorOne

![Platform](https://img.shields.io/badge/Platform-Windows%20x64-blue)
![Language](https://img.shields.io/badge/C%2B%2B-Kernel-orange)
![License](https://img.shields.io/badge/License-Reseacher-lightgrey)


DetectorOne is a Windows kernel-mode EDR research project focused on defensive detection of BYOVD-style activity. It monitors driver loading, inspects kernel driver imports, protects its own kernel callbacks with a canary mesh, and exposes kernel telemetry to a user-mode engine for enrichment and alerting.

> Status: research prototype. Use only inside an isolated Windows kernel debugging lab.

## Project Scope

The current lab is composed of three cooperating projects:

| Component | Path | Role |
| --- | --- | --- |
| `DetectorOne.sys` | `C:\User\xxxx\source\repos\DectectorOne` | Kernel EDR sensor, driver import analysis, callback registration, registry enforcement, telemetry producer. |
| `CanaryMesh.sys` | `C:\Users\xxxx\source\repos\CanaryMesh` | Collegial canary mesh that watches DetectorOne callback integrity and driver presence. |
| `DetectorOneEngine.exe` | `C:\Users\xxxx\source\repos\DetectorOneEngine` | User-mode telemetry consumer, formatter, alert dispatcher, and YARA-based enrichment layer. |

DetectorOne stays intentionally defensive. The project does not provide exploit primitives, arbitrary kernel read/write helpers, or tooling for loading vulnerable drivers.



## High-Level Architecture

```text
                         +-------------------------+
                         |  DetectorOneEngine.exe  |
                         |  - IOCTL telemetry poll |
                         |  - EngineLog output     |
                         |  - YARA enrichment      |
                         +------------^------------+
                                      |
                           \\.\KratosEDR IOCTLs
                                      |
+-------------------------+-----------+------------+-------------------------+
|                         DetectorOne.sys                                    |
|  - process/thread/image callbacks                                          |
|  - registry service callback                                               |
|  - driver IAT analysis and primitive scoring                               |
|  - pre-load blocking policy                                                |
|  - kernel telemetry ring buffer                                            |
|  - canary bootstrap and alert dispatch                                     |
+-------------------------+-----------+------------+-------------------------+
                                      |
                            callback baselines
                            alerts + liveness
                                      |
                         +------------v------------+
                         |      CanaryMesh.sys     |
                         |  - callback table scan  |
                         |  - liveness detection   |
                         |  - driver watch         |
                         |  - quorum consensus     |
                         +-------------------------+

```

# PoC

![Architecture](https://github.com/mukendi/DetectorOne/blob/main/1.png)
Fig: Image 1
![Architecture](https://github.com/mukendi/DetectorOne/blob/main/2.png)
Fig: Image 2
![Architecture](https://github.com/mukendi/DetectorOne/blob/main/3.png)
Fig: Image 3


## DetectorOne Kernel Sensor

DetectorOne creates the kernel device `\Device\KratosEDR` and exposes the user-mode device link `\\.\KratosEDR`. It is responsible for collecting the kernel signals that the rest of the system consumes.

Core responsibilities:

- register process, thread, image-load, and registry callbacks;
- inspect `.sys` image loads and driver service `ImagePath` writes;
- parse PE import tables and score sensitive kernel APIs;
- block clearly malicious driver classes before load when policy requires it;
- dispatch suspicious driver alerts to CanaryMesh;
- publish callback baseline addresses and liveness counters;
- push structured telemetry events into a kernel ring buffer;
- serve telemetry batches to user mode through `IOCTL_KRATOS_GET_EVENTS`.

Current DetectorOne source layout:

```text
DectectorOne/
`-- DectectorOne/
    |-- DriverEntry.cpp
    |-- header.h
    |-- DetectorOneCallbacks.cpp
    |-- DetectorOneCanaries.cpp
    |-- DetectorOneIatRegistry.cpp
    `-- DetectorOneTelemetry.cpp
```

The project now follows the normal `h + cpp` architecture. `DriverEntry.cpp` owns bootstrap and unload orchestration, while the feature areas are split into dedicated implementation files.

## Detection Model

DetectorOne combines pre-load and post-load analysis.

### Pre-Load Registry Enforcement

The registry callback watches driver service configuration under:

```text
\Registry\Machine\System\CurrentControlSet\Services\
```

When a service `ImagePath` points to a `.sys` file, DetectorOne attempts to resolve the path and analyze the file before the driver is loaded. The IAT parser detects sensitive imports and computes a risk score.

The policy must remain strict enough to stop real driver-killer behavior, but not so broad that a normal lab driver is blocked only because it imports one sensitive API. In the current model, a driver should be blocked early when it matches a high-confidence blocking category, such as a process-killer primitive based on `ZwTerminateProcess`. Lower-confidence primitives should normally generate telemetry and canary alerts instead of immediate blocking.

### Post-Load Image Notification

The image-load callback observes loaded kernel images and emits telemetry for driver loads. It also allows DetectorOne to alert CanaryMesh when a driver is suspicious but was not prevented during pre-load analysis.

### Sensitive Import Examples

Examples of sensitive imports tracked by DetectorOne:

| Import | Defensive meaning |
| --- | --- |
| `ZwTerminateProcess` | Possible EDR/process killer primitive. |
| `ZwOpenProcess` | Process access primitive, important in combination with termination or memory APIs. |
| `MmMapIoSpace` | Physical memory mapping primitive often seen in BYOVD abuse chains. |
| `MmGetPhysicalAddress` | Physical address discovery primitive. |
| `ZwMapViewOfSection` | Section mapping primitive used in memory manipulation chains. |
| `MmMapLockedPagesSpecifyCache` | Memory mapping primitive requiring context-sensitive scoring. |
| `PsSetCreateProcessNotifyRoutineEx` | Callback registration API, not automatically malicious by itself. |

## Kernel Telemetry

DetectorOne exposes telemetry through a ring buffer consumed by DetectorOneEngine. The user-mode engine polls the driver through `IOCTL_KRATOS_GET_EVENTS`.

Telemetry event classes currently expected by the engine:

| Event | Purpose |
| --- | --- |
| `PROCESS_CREATED` | New process with PID, parent PID, timestamp, and image path when available. |
| `PROCESS_TERMINATED` | Process exit notification. |
| `IMAGE_LOAD` | User-mode image or kernel driver image load. |
| `DRIVER_BLOCKED` | Driver blocked by pre-load policy. |
| `CANARY_ALERT` | CanaryMesh consensus or callback integrity alert. |
| `RWX_THREAD_START` | Thread start address associated with executable or suspicious memory. |
| `RWX_REGION` | Memory region with suspicious protection or execution context. |
| `DETECTOR_REGISTRY_SERVICE` | Driver service registry activity, including service name and image path. |

The telemetry path is intentionally batch-oriented. The kernel should keep callbacks short, enqueue compact event records, and let user mode perform heavier enrichment.

## CanaryMesh

CanaryMesh is a set of kernel canary drivers launched by DetectorOne during bootstrap. Each canary registers with DetectorOne, receives callback baselines, and independently checks whether DetectorOne is still visible in the kernel callback lists.

Current CanaryMesh source layout:

```text
CanaryMesh/
`-- CanaryMesh/
    |-- DriverEntry.cpp
    |-- CanaryMesh.h
    |-- CanaryMeshCallbackScan.cpp
    |-- CanaryMeshConsensus.cpp
    |-- CanaryMeshRegistration.cpp
    `-- CanaryMeshThreads.cpp
```

CanaryMesh tracks three main signals:

| Signal | Meaning |
| --- | --- |
| Signal A | DetectorOne callback pointer was removed from a kernel callback list. |
| Signal B | DetectorOne liveness counters stopped changing. |
| Signal C | The suspicious driver being watched is no longer loaded. |

When quorum is reached, CanaryMesh emits a collegial alert:

```text
[CanaryMesh CONSENSUS] *** COLLEGIAL ALERT ***
```

The consensus alert is refreshed every 60 seconds while the suspicious driver remains present. This is important for BYOVD scenarios where the attacker does not unload the EDR driver, but removes the EDR callback pointers from kernel notification arrays.

## DetectorOneEngine

DetectorOneEngine is the user-mode consumer for DetectorOne telemetry. It should be run as Administrator after `DetectorOne.sys` is loaded.

Current DetectorOneEngine source layout:

```text
DetectorOneEngine/
`-- DetectorOneEngine/
    |-- DetectorOneEngine.cpp
    |-- EngineHeader.h
    |-- EngineLog.h
    |-- TelemetryEngine.h
    |-- TelemetryEngine.cpp
    `-- YaraScanner.h
```

Core responsibilities:

- open `\\.\KratosEDR`;
- poll `IOCTL_KRATOS_GET_EVENTS`;
- decode `KernelTelemetryEvent` batches;
- format process, image, driver, registry, canary, and RWX telemetry;
- enrich suspicious memory or file-backed observations with YARA;
- centralize console/file output through `EngineLog`.

DetectorOneEngine is the right place for expensive analysis. Kernel callbacks should not compile YARA rules, scan large buffers, resolve rich metadata, or perform slow file operations.

### User-Mode Telemetry Pipeline

DetectorOneEngine is the user-mode half of the product. Its job is to consume the compact kernel events produced by `DetectorOne.sys`, enrich them, and present them in a form that can be used by an analyst or forwarded to a backend later.

The engine starts by opening:

```text
\\.\KratosEDR
```

This device name is backed by the kernel device created by DetectorOne:

```text
\Device\KratosEDR
```

Once the handle is open, the engine polls the kernel driver with `IOCTL_KRATOS_GET_EVENTS`. The driver returns batches of telemetry records instead of one event per call. This keeps the user/kernel boundary cheaper and avoids losing events during bursts.

Typical flow:

```text
DetectorOne kernel callback
        |
        v
KernelTelemetryEvent
        |
        v
DetectorOne telemetry ring buffer
        |
        v
IOCTL_KRATOS_GET_EVENTS
        |
        v
DetectorOneEngine::TelemetryEngine
        |
        +--> EngineLog console/file output
        +--> risk evaluation
        +--> YARA scan for selected memory/file observations
        +--> future backend dispatch
```

The engine currently focuses on these event families:

- process creation and termination;
- image loads, including kernel driver images;
- blocked driver attempts;
- registry service telemetry from `DETECTOR_REGISTRY_SERVICE`;
- RWX thread-start and RWX memory-region observations;
- CanaryMesh alerts and consensus results;
- YARA matches emitted from suspicious memory inspection.

This split is deliberate. DetectorOne should collect and enforce with minimal kernel work. DetectorOneEngine should perform heavier logic: formatting, correlation, YARA scanning, rule management, local logging, and future backend communication.

### Running DetectorOneEngine

Run the engine from an elevated console after the driver is loaded:

```powershell
C:\Users\xxx\source\repos\DetectorOneEngine\x64\Release\DetectorOneEngine.exe
```

Expected startup:

```text
[INFO    ] Device opened successfully: \\.\KratosEDR
[INFO    ] DetectorOneEngine initialized successfully
[INFO    ] Telemetry polling thread started
```

If the process exits immediately after `Device opened successfully`, inspect the engine log and verify that required runtime files are present beside the executable, especially YARA rule files and any required YARA runtime DLLs if the project is linked dynamically.

## YARA Integration

YARA is used in `DetectorOneEngine`, not in the kernel driver. This keeps DetectorOne stable and minimizes work performed at kernel IRQL-sensitive points.

The current engine integrates libyara through `YaraScanner.h`:

- `yr_initialize()` and `yr_finalize()` manage libyara lifetime;
- `LoadRulesFromFile(...)` compiles rules from disk;
- `ScanMemoryBuffer(...)` scans a memory buffer and returns matching rule names;
- `TelemetryEngine` loads `Windows_Trojan_CobaltStrike.yar` and scans suspicious RWX memory snapshots.

Current Visual Studio linkage points:

```text
YARA include path:
C:\Users\xxxx\yara\libyara\include

YARA library path:
C:\Users\xxxx\yara\windows\vs2019\libyara\Release

Linked library:
libyara64.lib
```

Operational guidance:

- keep YARA rules beside the engine executable or use a configured absolute rules directory;
- treat missing rules as a degraded enrichment state, not as a kernel failure;
- log rule name, namespace, PID, base address, and triggering telemetry event;
- keep YARA scanning focused on bounded buffers, for example suspicious RWX regions, not full arbitrary process memory;
- avoid putting YARA or large rule matching in `DetectorOne.sys`.

### Installing libyara for DetectorOneEngine

The current Visual Studio project is configured to use a local YARA tree under:

```text
C:\Users\xxxx\yara
```

Expected local layout:

```text
C:\Users\xxxx\yara\
|-- libyara\
|   `-- include\
|       `-- yara.h
`-- windows\
    `-- vs2019\
        `-- libyara\
            `-- Release\
                |-- libyara64.lib
                `-- libyara64.pdb
```

DetectorOneEngine currently includes YARA with:

```cpp
#include <yara.h>
```

The Visual Studio project must contain these settings for both `x64 Debug` and `x64 Release` configurations:

| Setting | Value |
| --- | --- |
| C/C++ > General > Additional Include Directories | `C:\Users\xxxx\yara\libyara\include;%(AdditionalIncludeDirectories)` |
| Linker > General > Additional Library Directories | `C:\Users\xxxx\yara\windows\vs2019\libyara\Release;%(AdditionalLibraryDirectories)` |
| Linker > Input > Additional Dependencies | `libyara64.lib;%(AdditionalDependencies)` |
| C/C++ > Language > C++ Language Standard | `ISO C++20 Standard (/std:c++20)` |

The current project file already contains the include directory, library directory, and `libyara64.lib` dependency. If the project is moved to another machine, those paths must be updated or replaced with Visual Studio macros such as `$(YARA_ROOT)`.

Recommended environment-variable based setup:

```powershell
setx YARA_ROOT "C:\Users\xxxx\yara"
```

Then the Visual Studio properties can be made portable:

```text
Additional Include Directories:
$(YARA_ROOT)\libyara\include;%(AdditionalIncludeDirectories)

Additional Library Directories:
$(YARA_ROOT)\windows\vs2019\libyara\Release;%(AdditionalLibraryDirectories)
```

If using a dynamic YARA build, copy the required DLLs beside the engine executable:

```text
C:\Users\xxxx\source\repos\DetectorOneEngine\x64\Release\
|-- DetectorOneEngine.exe
|-- libyara64.dll
`-- Windows_Trojan_CobaltStrike.yar
```

If using the current static library setup with `libyara64.lib`, the executable may still require runtime dependencies from the YARA build depending on how `libyara64.lib` was produced. Use `dumpbin /dependents DetectorOneEngine.exe` from a Developer Command Prompt to verify runtime DLL requirements.

### YARA Rule Loading

`TelemetryEngine` currently attempts to load:

```text
Windows_Trojan_CobaltStrike.yar
```

Place that rule file in the current working directory used to launch the engine, or change the engine to load rules from an absolute configured rule directory.

Current code path:

```text
TelemetryEngine::Initialize
  -> YaraScanner::LoadRulesFromFile("Windows_Trojan_CobaltStrike.yar")
  -> YaraScanner::ScanMemoryBuffer(...)
```

`YaraScanner` returns the matching rule identifier and namespace. DetectorOneEngine then logs matches in this form:

```text
[YARA MATCH] PID: <pid> | Region: <base> | Rules: <rule> (NS: <namespace>)
```

For production-quality behavior, the engine should not stop just because YARA rules are missing. A missing or invalid rule file should be logged as a medium-severity configuration issue while the telemetry consumer continues running.

```

## Build

Build the three projects from an elevated Developer Command Prompt or from Visual Studio.

DetectorOne kernel driver:

```powershell
msbuild "C:\Users\xxxx\source\repos\DectectorOne\DectectorOne.sln" /p:Configuration=Debug /p:Platform=x64
```

CanaryMesh:

```powershell
msbuild "C:\Users\xxxx\source\repos\CanaryMesh\CanaryMesh.sln" /p:Configuration=Debug /p:Platform=x64
```

DetectorOneEngine:

```powershell
msbuild "C:\Users\xxxx\source\repos\DetectorOneEngine\DetectorOneEngine.sln" /p:Configuration=Release /p:Platform=x64
```

Expected engine output:

```text
C:\Users\xxxx\source\repos\DetectorOneEngine\x64\Release\DetectorOneEngine.exe
```

## Lab Runbook

1. Boot a Windows VM configured for kernel debugging and test-signed drivers.
2. Load `DetectorOne.sys`.
3. Confirm that `\Device\KratosEDR` and `\\.\KratosEDR` are available.
4. Let DetectorOne bootstrap the CanaryMesh drivers.
5. Start `DetectorOneEngine.exe` as Administrator.
6. Confirm telemetry output for process creation, image loads, registry service events, RWX observations, and canary alerts.
7. Test benign drivers first to verify that the blocking policy is not too aggressive.
8. Test known suspicious drivers in an isolated lab and verify that high-confidence primitives are blocked or escalated to CanaryMesh.

## Expected Logs

DetectorOne kernel load:

```text
[DetectorOne] Device created: \Device\KratosEDR
[DetectorOne] Callbacks registered
[DetectorOne] Bootstrap: launching 3 canaries Quorum=2
[DetectorOne] Loaded
```

DetectorOneEngine startup:

```text
[INFO    ] Device opened successfully: \\.\KratosEDR
[INFO    ] DetectorOneEngine initialized successfully
[INFO    ] Telemetry polling thread started
```

CanaryMesh consensus:

```text
[CanaryMesh CONSENSUS] *** COLLEGIAL ALERT ***
[CanaryMesh CONSENSUS] Signal A        = 1 (callback pointer)
[CanaryMesh CONSENSUS] Votes           = 2/2
```

YARA enrichment:

```text
[YARA MATCH] PID: <pid> | Region: <base> | Rules: <rule> (NS: <namespace>)
```

## ABI Notes

The kernel driver, canaries, and engine share structure definitions and IOCTL contracts. Any change to the telemetry event layout, canary registration packet, alert packet, or IOCTL code must be updated across all consumers.

Pay particular attention to:

- structure packing and field sizes;
- `UNICODE_STRING` versus fixed-size user-mode buffers;
- pointer-sized fields crossing kernel/user boundaries;
- versioning telemetry records before adding fields;
- keeping kernel event payloads compact.

## Engineering Principles

- Keep kernel callbacks short and deterministic.
- Block only high-confidence primitives pre-load.
- Prefer telemetry and canary escalation for medium-confidence signals.
- Keep expensive enrichment in DetectorOneEngine.
- Use CanaryMesh to detect callback removal, not only driver unload.
- Preserve benign-driver compatibility as a first-class requirement.
- Treat YARA as an enrichment layer, not as a kernel enforcement dependency.

## Safety

This repository is intended for defensive research into Windows kernel sensor resilience. Run it only in controlled environments where crashes, bugchecks, and driver loading failures are acceptable.
