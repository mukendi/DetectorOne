#pragma once
#define NOMINMAX

#include "EngineHeader.h"
#include <yara.h>

class YaraScanner {
public:
    YaraScanner() {
        if (yr_initialize() != ERROR_SUCCESS) {
            EngineLog::Log(Severity::Error,"libyara initialization failed\n");
        }
    }

    ~YaraScanner() {
        if (m_rules) {
            yr_rules_destroy(m_rules);
        }
        yr_finalize();
    }

    // Prevents copying to preserve the YARA handle
    YaraScanner(const YaraScanner&) = delete;
    YaraScanner& operator=(const YaraScanner&) = delete;

    bool LoadRulesFromFile(const std::string& ruleFilePath) {
        YR_COMPILER* compiler = nullptr;
        if (yr_compiler_create(&compiler) != ERROR_SUCCESS) return false;

        FILE* ruleFile = nullptr;
        fopen_s(&ruleFile, ruleFilePath.c_str(), "r");

        if (!ruleFile) {
            yr_compiler_destroy(compiler);
            EngineLog::Log(Severity::Warning, "Could not open rule file.");
            return false;
        }

        int errors = yr_compiler_add_file(compiler, ruleFile, nullptr, ruleFilePath.c_str());
        fclose(ruleFile);

        if (errors > 0) {
            yr_compiler_destroy(compiler);
            return false;
        }

        //std::lock_guard lock(m_mutex);
        if (m_rules) yr_rules_destroy(m_rules);

        if (yr_compiler_get_rules(compiler, &m_rules) != ERROR_SUCCESS) {
            yr_compiler_destroy(compiler);
            return false;
        }

        yr_compiler_destroy(compiler);
        return true;
    }

    struct MatchResult {
        std::string RuleName;
        std::string Namespace;
    };

    std::vector<MatchResult> ScanMemoryBuffer(const uint8_t* buffer, size_t bufferSize) {
        std::vector<MatchResult> matches;
        if (!buffer || bufferSize == 0) return matches;

        std::lock_guard lock(m_mutex);

        // Callback called by YARA for each match found
        auto callback = [](YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) -> int {
            if (message == CALLBACK_MSG_RULE_MATCHING) {
                auto* rule = static_cast<YR_RULE*>(message_data);
                auto* matchResults = static_cast<std::vector<MatchResult>*>(user_data);
                matchResults->push_back({ rule->identifier, rule->ns->name ? rule->ns->name : "default" });
            }
            return CALLBACK_CONTINUE;
            };

        yr_rules_scan_mem(
            m_rules,
            const_cast<uint8_t*>(buffer),
            bufferSize,
            0,
            callback,
            &matches,
            0
        );

        return matches;
    }

private:
    YR_RULES* m_rules{ nullptr };
    std::mutex m_mutex;
};