#include "TelemetryEngine.h"
#include <algorithm>
#include <numeric>

bool TelemetryEngine::Initialize(std::wstring_view devicePath) {
    if (m_hDevice != INVALID_HANDLE_VALUE) {
        return true;
    }

    m_hDevice = ::CreateFileW(
        devicePath.data(),
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr
    );

    if (m_hDevice == INVALID_HANDLE_VALUE) {
        EngineLog::Log(Severity::Critical,
            "[!] Failed to open kernel communication channel | Device: {} | Error: {}",
            ToUtf8(devicePath), ::GetLastError());
        return false;
    }

    if (m_yaraEngine.LoadRulesFromFile("Windows_Trojan_CobaltStrike.yar")) {
        EngineLog::Log(Severity::Info, "[+] Yara Rules loaded with success.");
    }
    else {
        EngineLog::Log(Severity::Medium, "[!] Loading Yara Rules failed.");
    }

    EngineLog::Log(Severity::Info, "[+] Kernel channel successfully established on {}", ToUtf8(devicePath));
    return true;
}

void TelemetryEngine::Start() {
    if (m_running.exchange(true)) return;

    if (m_hDevice == INVALID_HANDLE_VALUE) {
        if (!Initialize(DeviceName)) {
            m_running = false;
            return;
        }
    }

    // Lancement des workers asynchrones (C++20 std::jthread)
    m_pollingThread = std::jthread([this](std::stop_token st) { PollingWorker(st); });
    m_heartbeatThread = std::jthread([this](std::stop_token st) { HeartbeatWorker(st); });

    EngineLog::Log(Severity::Info, "[ENGINE] Telemetry service started. Workers active.");
}

void TelemetryEngine::Stop() {
    if (!m_running.exchange(false)) return;

    // Signal d'arrêt coopératif
    m_pollingThread.request_stop();
    m_heartbeatThread.request_stop();

    if (m_pollingThread.joinable()) m_pollingThread.join();
    if (m_heartbeatThread.joinable()) m_heartbeatThread.join();

    if (m_hDevice != INVALID_HANDLE_VALUE) {
        ::CloseHandle(m_hDevice);
        m_hDevice = INVALID_HANDLE_VALUE;
    }

    EngineLog::Log(Severity::Info, "[ENGINE] Telemetry service stopped cleanly.");
}

void TelemetryEngine::PollingWorker(std::stop_token stopToken) {
    auto batch = std::make_unique<KernelEventBatch>();

    while (!stopToken.stop_requested()) {
        std::memset(batch.get(), 0, sizeof(KernelEventBatch));
        DWORD bytesReturned = 0;

        BOOL success = ::DeviceIoControl(
            m_hDevice,
            IoctlGetEvents,
            nullptr, 0,
            batch.get(), sizeof(KernelEventBatch),
            &bytesReturned, nullptr
        );

        if (success && batch->Count > 0) {
            ProcessBatch(*batch);
        }
        else {
            std::this_thread::sleep_for(std::chrono::milliseconds(PollIntervalMs));
        }
    }
}

void TelemetryEngine::HeartbeatWorker(std::stop_token stopToken) {
    while (!stopToken.stop_requested()) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        if (stopToken.stop_requested()) break;

        EngineLog::Log(Severity::Info,
            "[HEARTBEAT] Status: OK | Processed Events: {} | Critical Detections: {}",
            m_eventsProcessed.load(std::memory_order_relaxed),
            m_highRiskAlerts.load(std::memory_order_relaxed)
        );
    }
}

void TelemetryEngine::ProcessBatch(const KernelEventBatch& batch) {
    ULONG count = std::min<ULONG>(batch.Count, MaxEventsPerBatch);

    for (ULONG i = 0; i < count; ++i) {
        DispatchEvent(batch.Events[i]);
        EvaluateRisk(batch.Events[i]);
    }

    m_eventsProcessed.fetch_add(count, std::memory_order_relaxed);
}

void TelemetryEngine::DispatchEvent(const KernelTelemetryEvent& event) {
    auto type = static_cast<EventType>(event.Type);
    std::string path = ToUtf8(event.ImagePath);

    switch (type) {
    case EventType::RwxRegion:
    case EventType::RwxThreadStart: {
        // Inspection heuristique de l'en-tête RWX (12 octets)
        RwxAnalysisResult analysis = InspectRwxMemory(event.ProcessId, event.Address, 12);

        if (analysis.IsSuspicious) {
            m_highRiskAlerts.fetch_add(1, std::memory_order_relaxed);

            EngineLog::Log(Severity::Critical,
                "[SHELLCODE_ALERT] Malicious RWX Payload Detected\n"
                "  ├─ Target Process : PID {}\n"
                "  ├─ Memory Region  : {:#018x} ({} bytes)\n"
                "  ├─ Hex Signature  : {}\n"
                "  └─ Indicators     : {}",
                event.ProcessId, event.Address, event.RegionSize, analysis.HexDump, analysis.DetectionReason);
        }
        else {
            EngineLog::Log(Severity::Warning,
                "[RWX_INSPECT] Executable-Writable Region | PID: {:<6} | Addr: {:#018x} | Size: {:<6} B | Hex: {}",
                event.ProcessId, event.Address, event.RegionSize, analysis.HexDump);
        }
        break;
    }

    case EventType::ProcessCreate:
        EngineLog::Log(Severity::Info, "[PROC_CREATE] PID: {:<6} | Path: {}", event.ProcessId, path);
        break;

    case EventType::ProcessExit:
        EngineLog::Log(Severity::Info, "[PROC_EXIT]   PID: {:<6}", event.ProcessId);
        break;

    default:
        break;
    }
}

void TelemetryEngine::EvaluateRisk(const KernelTelemetryEvent& event) {
    if (event.RiskScore >= 80) {
        m_highRiskAlerts.fetch_add(1, std::memory_order_relaxed);
        EngineLog::Log(Severity::Critical,
            "[RISK_EVAL] Threat threshold exceeded | PID: {:<6} | Risk Score: {}/100",
            event.ProcessId, event.RiskScore);
    }
}

RwxAnalysisResult TelemetryEngine::InspectRwxMemory(uint64_t processId, uint64_t baseAddress, size_t bytesToInspect) {
    RwxAnalysisResult result{};

    UniqueHandle hProcess(::OpenProcess(PROCESS_VM_READ, FALSE, static_cast<DWORD>(processId)));
    if (!hProcess || hProcess.get() == INVALID_HANDLE_VALUE) {
        result.DetectionReason = std::format("OpenProcess failed (Error: {})", ::GetLastError());
        return result;
    }

    std::vector<uint8_t> buffer(bytesToInspect, 0);
    SIZE_T bytesRead = 0;

    BOOL readSuccess = ::ReadProcessMemory(
        hProcess.get(),
        reinterpret_cast<LPCVOID>(baseAddress),
        buffer.data(),
        buffer.size(),
        &bytesRead
    );

    if (!readSuccess || bytesRead == 0) {
        result.DetectionReason = std::format("ReadProcessMemory failed at {:#018x} (Error: {})", baseAddress, ::GetLastError());
        return result;
    }

    /*
    auto yaraMatches = m_yaraEngine.ScanMemoryBuffer(buffer.data(), bytesRead);

    if (!yaraMatches.empty()) {
        for (const auto& match : yaraMatches) {
            EngineLog::Log(
                Severity::Critical,
                "[YARA MATCH] PID: {} | Region: {:#x} | Rules: {} (NS: {})",
                processId, baseAddress, match.RuleName, match.Namespace
            );
        }
        m_highRiskAlerts.fetch_add(1, std::memory_order_relaxed);
        result.IsSuspicious = true;
        result.DetectionReason = std::format("YARA match: {}", yaraMatches[0].RuleName);;

        return result;
    }*/
    // Formatage Hex Dump propre (ex: "FC 48 83 EC ...")
    std::string hexStr;
    for (size_t i = 0; i < bytesRead; ++i) {
        hexStr += std::format("{:02X} ", buffer[i]);
    }
    if (!hexStr.empty()) hexStr.pop_back(); // Retrait de l'espace final
    result.HexDump = hexStr;

    // Heuristique de détection de shellcode
    uint32_t score = 0;
    std::vector<std::string> indicators;

    // Check A: NOP Sled (0x90)
    size_t nopCount = std::count(buffer.begin(), buffer.end(), 0x90);
    if (nopCount >= 4) {
        score += 40;
        indicators.push_back(std::format("NOP sled pattern ({}/{} bytes)", nopCount, bytesRead));
    }

    // Check B: Segment Override GS/FS (x64/x86 TEB access)
    if (buffer[0] == 0x65 || buffer[0] == 0x64 || (bytesRead > 1 && (buffer[1] == 0x65 || buffer[1] == 0x64))) {
        score += 50;
        indicators.push_back("TEB/PEB segment override (GS/FS)");
    }

    // Check C: Shellcode Entry Prologues (Metasploit / Cobalt Strike)
    if (buffer[0] == 0xFC) {
        score += 30;
        indicators.push_back("CLD instruction (Metasploit header)");
    }
    if (bytesRead >= 3 && buffer[0] == 0x48 && buffer[1] == 0x83 && buffer[2] == 0xEC) {
        score += 25;
        indicators.push_back("Stack allocation (SUB RSP, imm8)");
    }
    if (bytesRead >= 2 && buffer[0] == 0x48 && buffer[1] == 0x31) {
        score += 25;
        indicators.push_back("Register zeroing (XOR R64)");
    }

    // Check D: Jump/Call Relatif initial
    if (buffer[0] == 0xEB || buffer[0] == 0xE9 || buffer[0] == 0xE8) {
        score += 20;
        indicators.push_back("Relative JMP/CALL entrypoint");
    }

    if (score >= 40) {
        result.IsSuspicious = true;
        result.DetectionReason = std::format("Score: {}/100 | Flags: [{}]", score,
            std::accumulate(indicators.begin(), indicators.end(), std::string(),
                [](const std::string& a, const std::string& b) { return a.empty() ? b : a + " | " + b; }));
    }

    return result;
}