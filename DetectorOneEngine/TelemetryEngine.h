#pragma once

#include "EngineHeader.h"
#include "EngineLog.h"
#include "YaraScanner.h"

struct RwxAnalysisResult {
    bool IsSuspicious{ false };
    std::string DetectionReason;
    std::string HexDump;
};

struct HandleDeleter {
    using pointer = HANDLE; // Dictates the type std::unique_ptr uses internally

    void operator()(HANDLE handle) const {
        if (handle != INVALID_HANDLE_VALUE && handle != nullptr) {
            CloseHandle(handle);
        }
    }
};

// Create a clean type alias for readability
using UniqueHandle = std::unique_ptr<HANDLE, HandleDeleter>;


class TelemetryEngine {
public:
    TelemetryEngine() = default;
    ~TelemetryEngine() { Stop(); }

    TelemetryEngine(const TelemetryEngine&) = delete;
    TelemetryEngine& operator=(const TelemetryEngine&) = delete;
    TelemetryEngine(TelemetryEngine&&) noexcept = default;
    TelemetryEngine& operator=(TelemetryEngine&&) noexcept = default;

    bool Initialize(std::wstring_view devicePath);
    void Start();
    void Stop();

    [[nodiscard]] bool IsRunning() const noexcept {
        return m_running.load(std::memory_order_relaxed);
    }
    [[nodiscard]] uint64_t GetProcessedEventsCount() const noexcept {
        return m_eventsProcessed.load(std::memory_order_relaxed);
    }
    [[nodiscard]] uint64_t GetHighRiskAlertsCount() const noexcept {
        return m_highRiskAlerts.load(std::memory_order_relaxed);
    }

private:
    // Asynchronous execution loops (C++20 std::jthread)
    void PollingWorker(std::stop_token stopToken);
    void HeartbeatWorker(std::stop_token stopToken);

    // Ingestion and analysis routines
    void ProcessBatch(const KernelEventBatch& batch);
    void DispatchEvent(const KernelTelemetryEvent& event);
    void EvaluateRisk(const KernelTelemetryEvent& event);

    RwxAnalysisResult InspectRwxMemory(uint64_t processId, uint64_t baseAddress, size_t bytesToInspect);

    //using Clock = std::chrono::steady_clock;
    //std::unordered_map<ULONG, Clock::time_point> m_lastAlertTime;
    //std::mutex m_alertTimeMutex;


    HANDLE m_hDevice{ INVALID_HANDLE_VALUE };
    std::jthread m_pollingThread;
    std::jthread m_heartbeatThread;

    std::atomic<bool> m_running{ false };
    std::atomic<uint64_t> m_eventsProcessed{ 0 };
    std::atomic<uint64_t> m_highRiskAlerts{ 0 };

    YaraScanner m_yaraEngine;
};