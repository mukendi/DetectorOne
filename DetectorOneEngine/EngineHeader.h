#pragma once
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <winhttp.h>

#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <thread>
#include <stop_token>
#include <mutex>
#include <atomic>
#include <chrono>
#include <array>


#include <unordered_map>
#include <iostream>
#include <format>
#include <numeric>
#include <iomanip>
#include <sstream>
#include <yara.h>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "winhttp.lib")

inline constexpr std::wstring_view DeviceName{ L"\\\\.\\KratosEDR" };
inline constexpr std::wstring_view LogFileName{ L"KratosEDR_Engine.log" };
inline constexpr std::wstring_view EtwSessionName{ L"KratosEDR_ETW_Session" };

constexpr uint32_t PollIntervalMs = 250;
constexpr std::chrono::seconds HeartbeatInterval{ 30 };
constexpr uint32_t MaxEventsPerBatch = 256;
constexpr uint32_t EventTextMax = 260;

// IOCTLs
constexpr DWORD IoctlGetEvents = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr DWORD IoctlGetTable = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);

enum class Severity : uint32_t {
    Info = 0,
    Warning,
    Error,
    Low,
    Medium,
    High,
    Critical
};

enum class EventType : uint32_t {
    ProcessCreate = 1,
    ProcessExit = 2,
    ThreadCreate = 3,
    ThreadExit = 4,
    ImageLoad = 5,
    DriverBlocked = 6,
    CanaryAlert = 7,
    RwxThreadStart = 9,
    RwxRegion = 10,
    RegistryService = 11
};

#pragma pack(push, 8)
struct KernelTelemetryEvent {
    uint32_t Size;
    uint32_t Type;
    uint64_t Sequence;
    LARGE_INTEGER Timestamp;
    uint64_t ProcessId;
    uint64_t ParentProcessId;
    uint64_t ThreadId;
    uint64_t Address;
    uint64_t RegionSize;
    uint32_t Protection;
    uint32_t RiskScore;
    uint32_t Flags;
    wchar_t ImagePath[EventTextMax];
    wchar_t Detail[64];
};

struct KernelEventBatch {
    uint32_t Version;
    uint32_t Count;
    uint32_t DroppedEvents;
    uint32_t Reserved;
    KernelTelemetryEvent Events[MaxEventsPerBatch];
};

struct EngineStats {
    uint32_t ProcessEventsTotal;
    uint32_t ThreadEventsTotal;
    uint32_t ImageLoadEventsTotal;
    uint32_t RegistryEventsTotal;
    uint32_t HighRiskDriversDetected;
    uint32_t DriversBlocked;
    uint32_t ConsensusAlertsGenerated;
    uint32_t ActiveCanaries;
    uint32_t QuorumRequired;
    int64_t  ProcessEventCounter;
    int64_t  ImageEventCounter;
    LARGE_INTEGER DriverLoadTime;
    wchar_t  SuspectDriverName[260];
};
#pragma pack(pop)


inline std::string ToUtf8(std::wstring_view wstr) {
    if (wstr.empty()) return {};
    int size = ::WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
    std::string result(size, 0);
    ::WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), result.data(), size, nullptr, nullptr);
    return result;
}

inline std::string FormatTimestamp(LARGE_INTEGER ts) {
    FILETIME ft;
    SYSTEMTIME st;
    ft.dwLowDateTime = ts.LowPart;
    ft.dwHighDateTime = static_cast<DWORD>(ts.HighPart);
    ::FileTimeToSystemTime(&ft, &st);
    return std::format("{:02}/{:02}/{:04} {:02}:{:02}:{:02}.{:03}",
        st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

inline std::string FormatHexDump(const uint8_t* data, size_t length) {
    if (!data || length == 0) return "";

    std::ostringstream ss;

    for (size_t i = 0; i < length; ++i) {
        ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
            << static_cast<int>(data[i]);

        if (i < length - 1) {
            ss << " ";
        }
    }

    return ss.str();
}
