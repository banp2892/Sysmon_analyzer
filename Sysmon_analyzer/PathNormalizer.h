#include <iostream>
#include <string>
#include <vector>
#include <regex>

inline std::wstring NormalizePathFunc(std::wstring input) {
    struct PathRule {
        std::wregex pattern;
        std::wstring replacement;
    };

    // static гарантирует, что правила создадутся ОДИН РАЗ за всё время работы программы
    static const std::vector<PathRule> rules = []() {
        std::vector<PathRule> r;

        // 1. GUID и SID
        r.push_back({ std::wregex(L"s-1-5-[0-9]{1,2}(?:(?:-[0-9]{10}){3}-[0-9]{3,4})?"), L"<user>" });
        r.push_back({ std::wregex(L"[{]?[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}[}]?"), L"<guid>" });

        // 2. Пользователи
        r.push_back({ std::wregex(L"c:\\\\users\\\\[^\\\\]+\\\\", std::regex_constants::icase), L"c:\\\\users\\\\<user>\\\\" });

        // 3. Системные директории
        r.push_back({ std::wregex(L"^c:\\\\windows\\\\system32", std::regex_constants::icase), L"[system]" });
        r.push_back({ std::wregex(L"^c:\\\\windows\\\\syswow64", std::regex_constants::icase), L"[system x86]" });
        r.push_back({ std::wregex(L"^c:\\\\windows", std::regex_constants::icase), L"[windows]" });

        // 4. Программные папки
        r.push_back({ std::wregex(L"^c:\\\\program files \\(x86\\)", std::regex_constants::icase), L"[program files x86]" });
        r.push_back({ std::wregex(L"^c:\\\\program files", std::regex_constants::icase), L"[program files]" });

        // 5. Временные файлы и цифры
        r.push_back({ std::wregex(L"\\\\temp", std::regex_constants::icase), L"[temp]" });
        r.push_back({ std::wregex(L"[0-9]{6,}"), L"<num>" });
        r.push_back({ std::wregex(L"0x[a-f0-9]{4,}"), L"<hex>" });

        // 6. Сеть
        r.push_back({ std::wregex(L"(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"), L"<ip>" });
        r.push_back({ std::wregex(L"https?://[^\\s/$.?#].[^\\s]*"), L"<url>" });

        return r;
        }();

    std::wstring result = input;
    for (const auto& rule : rules) {
        result = std::regex_replace(result, rule.pattern, rule.replacement);
    }
    return result;
}