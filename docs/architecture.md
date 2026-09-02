# DetectorOne Architecture

This document describes DetectorOne from a kernel engineering perspective: initialization order, callback ownership, BYOVD decision flow, and canary coordination.

## Design Goals

DetectorOne is designed around four defensive goals:

1. Observe driver activity as close as possible to the kernel load path.
2. Inspect driver import capabilities before or immediately after load.
3. Escalate long-lived high-risk primitives to independent canaries.
4. Detect attempts to blind the EDR callbacks or degrade the canary quorum.

## Initialization Sequence

`DriverEntry` performs initialization in this order:

1. Initialize telemetry stores:
   - process list;
   - thread list;
   - RWX AVL table;
   - service table;
   - synchronization primitives.
2. Create `\Device\KratosEDR`.
3. Create `\DosDevices\KratosEDR`.
4. Register IRP handlers.
5. Register process callback.
6. Register thread callback.
7. Register image-load callback.
8. Register registry callback.
9. Bootstrap CanaryMesh services.
10. Publish `DriverUnload`.

The canary mesh is started only after DetectorOne callbacks are installed. This guarantees the exported callback baseline reflects the actual active callback addresses.

## Callback Ownership

DetectorOne owns four primary callback channels.

| Callback | Purpose | Defensive Signal |
| --- | --- | --- |
| `PsSetCreateProcessNotifyRoutineEx` | process inventory and liveness | canary Signal B |
| `PsSetCreateThreadNotifyRoutine` | thread telemetry | execution context |
| `PsSetLoadImageNotifyRoutine` | loaded driver inspection | BYOVD post-load detection |
| `CmRegisterCallbackEx` | service `ImagePath` writes | BYOVD pre-load enforcement |

The canary mesh receives DetectorOne callback addresses and liveness counters. Canaries can then validate that the callbacks remain present and active after a suspicious driver appears.

## BYOVD Decision Flow

```text
Driver service ImagePath write
        |
        v
Registry pre-load callback
        |
        v
Resolve driver path and read .sys
        |
        v
Parse PE import table
        |
        v
Score dangerous imports
        |
        v
Classify primitive category
        |
        +--> block ImagePath write
        |
        +--> allow and track service
```

Post-load path:

```text
Kernel .sys image-load notification
        |
        v
Parse mapped image IAT
        |
        v
Score and classify
        |
        +--> immediate unload for narrow process-killer category
        |
        +--> dispatch canary alert for memory/MSR/arbitrary-RW/combo categories
```

## Primitive Categories

| Category | Meaning | Typical Response |
| --- | --- | --- |
| `PRIMITIVE_DRIVER_KILLER` | process termination without physical memory primitive | immediate block or unload |
| `PRIMITIVE_PHYSICAL_MEMORY` | physical memory mapping capability | canary surveillance |
| `PRIMITIVE_MSR_PORT_IO` | MSR or port I/O capability | canary surveillance |
| `PRIMITIVE_ARBITRARY_RW` | section mapping or arbitrary R/W-style primitive | canary surveillance |
| `PRIMITIVE_COMBO` | multiple dangerous capabilities | block or canary surveillance |

## Canary Mesh Contract

CanaryMesh registers through `IOCTL_KRATOS_REGISTER`.

Registration input:

- canary ID;
- canary driver object address;
- canary alert entry point.

Registration output:

- status;
- shared table pointer;
- DetectorOne process callback address;
- DetectorOne image callback address;
- DetectorOne thread callback address;
- process event counter pointer;
- image event counter pointer.

The shared table also carries:

- registered/alive canary counts;
- quorum requirement;
- alert generation and vote state;
- suspect driver name and load state;
- shutdown coordination.

## Unload Order

DetectorOne unload is intentionally ordered:

1. Set global unloading state.
2. Signal canaries that DetectorOne is shutting down.
3. Delay briefly so canary worker loops can exit their current iteration.
4. Unload canary services with `ZwUnloadDriver`.
5. Remove DetectorOne callbacks.
6. Free shared canary table.
7. Delete symbolic link and device object.
8. Free process/thread/RWX telemetry.

This prevents canaries from reading DetectorOne-owned memory after it has been released.

## Known Technical Debt

- `header.h` owns static globals. This is why implementation files are currently included as `.inl` blocks.
- The shared ABI should eventually move to a dedicated `KratosShared.h` used by both DetectorOne and CanaryMesh.
- The PE parser is intentionally bounded, but should continue receiving malformed-driver tests.
- The INF metadata still contains placeholder manufacturer text.
- Logging is `DbgPrint`-based and should eventually gain structured event output for SOC integration.

## Recommended Next Refactor

The next safe refactor is:

1. Create `KratosShared.h` for cross-driver structs and IOCTL codes.
2. Move global definitions to one `DetectorOneState.cpp`.
3. Convert `header.h` globals to `extern`.
4. Compile the current `.inl` files as real `.cpp` files.
5. Add a small test harness for PE/IAT parsing with malformed inputs.
