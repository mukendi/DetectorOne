#pragma once

#include "EngineHeader.h"

class EngineLog {
public:
    template<typename... Args>
    static void Log(Severity severity, std::format_string<Args...> fmt, Args&&... args) {
        std::string message = std::format(fmt, std::forward<Args>(args)...);
        WriteMessage(severity, message);
    }

private:
    
    static void EnableVirtualTerminal() noexcept {
        static const bool initialized = []() {
            HANDLE hOut = ::GetStdHandle(STD_OUTPUT_HANDLE);
            if (hOut == INVALID_HANDLE_VALUE) return false;

            DWORD dwMode = 0;
            if (!::GetConsoleMode(hOut, &dwMode)) return false;

            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            return ::SetConsoleMode(hOut, dwMode) != FALSE;
            }();
        (void)initialized;
    }

    static void WriteMessage(Severity severity, std::string_view message) {
        EnableVirtualTerminal();

        constexpr std::string_view ANSI_RESET = "\033[0m";
        constexpr std::string_view ANSI_CRIT = "\033[91;1m"; // Rouge Vif + Gras
        constexpr std::string_view ANSI_HIGH = "\033[38;2;255;140;0m"; // Orange (RGB)
        constexpr std::string_view ANSI_WARN = "\033[93m";   // Jaune Vif
        constexpr std::string_view ANSI_INFO = "\033[96m";   // Cyan Vif

        std::string_view prefix;
        std::string_view color;

        switch (severity) {
        case Severity::Critical:
            prefix = "[CRIT]";
            color = ANSI_CRIT;
            break;
        case Severity::High:
            prefix = "[HIGH]";
            color = ANSI_HIGH;
            break;
        case Severity::Warning:
            prefix = "[WARN]";
            color = ANSI_WARN;
            break;
        case Severity::Info:
        default:
            prefix = "[INFO]";
            //color = ANSI_INFO;
            break;
        }

        
        std::cout << color << prefix << " " << message << ANSI_RESET << "\n";

    }
};