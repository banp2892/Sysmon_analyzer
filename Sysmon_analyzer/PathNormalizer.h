#include <iostream>
#include <string>
#include <vector>
#include <regex>

/**
 * @struct PathRule
 * @brief Структура для хранения правила замены на основе регулярных выражений.
 */
struct PathRule {
    std::wregex pattern;      ///< Регулярное выражение для поиска
    std::wstring replacement; ///< Строка, на которую производим замену
};

/**
 * @class PathNormalizer
 * @brief Класс для преобразования системных путей в абстрактные токены (по Берлину).
 */
class PathNormalizer {
public:
    PathNormalizer() {
        // Инициализируем правила в порядке их следования в таблице
        // Важно: правила от частных к общим!

        // 1. Обработка GUID и SID (User)
        rules.push_back({ std::wregex(L"s-1-5-[0-9]{1,2}(?:(?:-[0-9]{10}){3}-[0-9]{3,4})?"), L"<user>" });
        rules.push_back({ std::wregex(L"[{]?[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}[}]?"), L"<guid>" });

        // 2. Пользовательские пути
        rules.push_back({ std::wregex(L"c:\\\\users\\\\[^\\\\]+\\\\", std::regex_constants::icase), L"c:\\\\users\\\\<user>\\\\" });

        // 3. Системные директории (Важен порядок!)
        rules.push_back({ std::wregex(L"^c:\\\\windows\\\\system32", std::regex_constants::icase), L"[system]" });
        rules.push_back({ std::wregex(L"^c:\\\\windows\\\\syswow64", std::regex_constants::icase), L"[system x86]" });
        rules.push_back({ std::wregex(L"^c:\\\\windows", std::regex_constants::icase), L"[windows]" });

        // 4. Программные папки
        rules.push_back({ std::wregex(L"^c:\\\\program files \\(x86\\)", std::regex_constants::icase), L"[program files x86]" });
        rules.push_back({ std::wregex(L"^c:\\\\program files", std::regex_constants::icase), L"[program files]" });

        // 5. Временные папки и специфические токены
        rules.push_back({ std::wregex(L"\\\\temp", std::regex_constants::icase), L"[temp]" });

        // 6. Реестр
        rules.push_back({ std::wregex(L"\\\\registry\\\\machine", std::regex_constants::icase), L"[registry (machine)]" });
        rules.push_back({ std::wregex(L"\\\\registry\\\\user\\\\<user>", std::regex_constants::icase), L"[registry (user)]\\\\<user>" });

        // 7. Очистка динамических параметров Cmd (порты, хендлы, числа)
// Заменяем длинные последовательности цифр (6+) на токен <num>
        rules.push_back({ std::wregex(L"[0-9]{6,}"), L"<num>" });

        // Очистка HEX-последовательностей (часто в именах драйверов или ключах)
        rules.push_back({ std::wregex(L"0x[a-f0-9]{4,}"), L"<hex>" });

        // 8. Агрессивная нормализация аргументов Chrome/Browsers 
        // (вырезаем специфические динамические флаги, оставляя только суть)
        rules.push_back({ std::wregex(L"--mojo-platform-channel-handle=<num>"), L"--mojo-handle" });
        rules.push_back({ std::wregex(L"--field-trial-handle=<num>,i,<num>,<num>,<num>"), L"--field-trial" });
        // 9. Сетевые признаки: замена IP-адресов на токен <ip>
        // Регулярка для IPv4
        rules.push_back({ std::wregex(L"(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"), L"<ip>" });

        // 10. Очистка URL (оставляем протокол и домен, убираем длинные хвосты)
        // Это поможет поймать загрузчики (downloaders)
        rules.push_back({ std::wregex(L"https?://[^\\s/$.?#].[^\\s]*"), L"<url>" });

        // 11. Почтовые адреса (иногда встречаются в Cmd фишинговых скриптов)
        rules.push_back({ std::wregex(L"[\\w.-]+@[\\w.-]+\\.[a-zA-Z]{2,}"), L"<email>" });
        // 12. Локальные адреса и петля (Loopback)
        rules.push_back({ std::wregex(L"127\\.0\\.0\\.1|::1|localhost", std::regex_constants::icase), L"<localhost>" });

        // 13. Частные подсети (твоя домашняя сеть 192.168.x.x и т.д.)
        rules.push_back({ std::wregex(L"192\\.168\\.[0-9]{1,3}\\.[0-9]{1,3}"), L"<local_net>" });
        rules.push_back({ std::wregex(L"10\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"), L"<local_net>" });
        rules.push_back({ std::wregex(L"172\\.(1[6-9]|2[0-9]|3[0-1])\\.[0-9]{1,3}\\.[0-9]{1,3}"), L"<local_net>" });

        // 14. Любой другой внешний IPv4 (чтобы скрыть конкретику, но оставить факт выхода в мир)
        rules.push_back({ std::wregex(L"(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"), L"<external_ip>" });

        // 15. Доменные имена (убираем поддомены, оставляем только суть для нейронки)
        // Например: la-in-f101.1e100.net -> <subdomain>.1e100.net
        rules.push_back({ std::wregex(L"[a-z0-9-]+\\.[a-z0-9-]+\\.(?:com|net|org|ru|app|io)"), L"<domain>" });
    
    
    }

    /**
     * @brief Применяет все правила нормализации к строке.
     * @param input Исходный путь или командная строка.
     * @return std::wstring Нормализованная строка.
     */
    std::wstring Normalize(std::wstring input) {
        std::wstring result = input;
        for (const auto& rule : rules) {
            result = std::regex_replace(result, rule.pattern, rule.replacement);
        }
        return result;
    }

private:
    std::vector<PathRule> rules;
};