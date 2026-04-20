#pragma once
#include <windows.h>
#include <string>
#include <variant>

/** * @struct ProcessData
 * @brief Данные события создания процесса (ID 1).
 */
struct ProcessData {
    std::wstring processGuid;  ///< Уникальный Id Sysmon
    std::wstring imagePath;    ///< Путь к исполняемому файлу
    std::wstring commandLine;  ///< Командная строка запуска
    double entropy;            ///< Вычисленная энтропия строки (заполнит PreparationData)
    DWORD processId;           ///< ID созданного процесса
    DWORD parentProcessId;     ///< ID родительского процесса
};

/** * @struct NetworkData
 * @brief Данные сетевого события (ID 3).
 */
struct NetworkData {
    std::wstring processGuid;  ///< Уникальный Id Sysmon
    std::wstring imagePath;    ///< Путь к процессу, инициировавшему соединение
    std::wstring destIp;       ///< IP-адрес назначения
    DWORD destPort;            ///< Порт назначения
    std::wstring protocol;     ///< Протокол (tcp/udp)
};

/** * @struct FileData
 * @brief Данные события создания/изменения файла (ID 11).
 */
struct FileData {
    std::wstring imagePath;    ///< Кто изменил
    std::wstring targetFilename; ///< Какой файл
    std::wstring creationTime; ///< Время создания
};

/** * @struct SysmonEvent
 * @brief Универсальный транспортный контейнер.
 */
struct SysmonEvent {
    long long timestamp;       ///< Время события (из заголовка ETW)
    int eventId;               ///< ID события (1, 3, 11 и т.д.)

    // variant позволяет хранить одну из структур в одном блоке памяти
    std::variant<ProcessData, NetworkData, FileData> eventData;
};