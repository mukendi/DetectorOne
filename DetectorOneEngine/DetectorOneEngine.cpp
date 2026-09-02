// Copyright (c) 2026, Simon Ngoy. All rights reserved.
// Use of this source code is governed by a MIT license.
//

#include "TelemetryEngine.h"
#include <atomic>
#include <iostream>


std::atomic<bool> g_SignalStop{ false };


BOOL WINAPI ConsoleHandler(DWORD signal) {
    switch (signal) {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        g_SignalStop.store(true, std::memory_order_relaxed);
        return TRUE;
    default:
        return FALSE;
    }
}


[[nodiscard]] bool IsProcessElevated() noexcept {
    BOOL elevated = FALSE;
    HANDLE hToken = nullptr;

    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation{};
        DWORD cbSize = sizeof(TOKEN_ELEVATION);

        if (::GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
            elevated = elevation.TokenIsElevated;
        }
        ::CloseHandle(hToken);
    }
    return elevated != FALSE;
}

int main() {
    ::SetConsoleOutputCP(CP_UTF8);
    ::SetConsoleCP(CP_UTF8);
    ::SetConsoleCtrlHandler(ConsoleHandler, TRUE);


    EngineLog::Log(Severity::Info, "==========================================================");
    EngineLog::Log(Severity::Info, "[+] DetectorOneEngine                                    =");
    EngineLog::Log(Severity::Info, "[+] Type : Engine                                        =");                                    
    EngineLog::Log(Severity::Info, "[+] Version : 1.0                                        =");
    EngineLog::Log(Severity::Info, "[+] Target Environment : Windows NT x64 (Kernel Mode)    =");
    EngineLog::Log(Severity::Info, "==========================================================");

    if (!IsProcessElevated()) {
        EngineLog::Log(Severity::Critical,
            "[!] DetectorOneEngine requires Administrator privileges to open kernel symlinks.");
        return 1;
    }

    TelemetryEngine engine;

    if (!engine.Initialize(DeviceName)) {
        EngineLog::Log(Severity::Critical, "[!] Agent initialization failed. Aborting startup.");
        return 1;
    }

    engine.Start();
    EngineLog::Log(Severity::Info, "[!] Press Ctrl+C or terminate process to stop agent.");

    while (!g_SignalStop.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    EngineLog::Log(Severity::Warning, "[!] Shutdown signal received. Stopping worker threads...");
    engine.Stop();

    return 0;
}