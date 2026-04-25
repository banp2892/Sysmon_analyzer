#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <set>
#include <iostream>
#include <variant>

#include "Structures.h"
#include "PathNormalizer.h"

struct ProcessNode {

    /// @name Статическая информация (ID 1: Process Creation)
    /// @{
    std::wstring Guid;               ///< [ProcessGuid] Уникальный идентификатор процесса в Sysmon
    DWORD PID;                       ///< [ProcessId] Числовой идентификатор процесса
    std::wstring ParentGuid;         ///< [ParentProcessGuid] GUID родительского процесса
    std::wstring ImagePath;          ///< [Image] Полный путь к исполняемому файлу
    std::wstring CommandLine;        ///< [CommandLine] Полная строка запуска процесса
    std::wstring User;               ///< [User] Пользователь, от имени которого запущен процесс
    /// @}

    /// @name Статистика командной строки
    /// @{
    float CmdEntropy = 0.0f;         ///< Энтропия Шеннона для командной строки (детект обфускации)
    size_t CmdLength = 0;            ///< Длина командной строки (Command_Line_Length)
    float SpecialCharDensity = 0.0f; ///< Плотность спецсимволов (Special_Char_Density)
    bool HasBase64 = false;          ///< Флаг присутствия признаков Base64 кодирования
    /// @}

    /// @name Иерархические и системные признаки
    /// @{
    bool IsInSystem32 = false;       ///< Флаг запуска из системной директории (Image_Location_Token)
    bool IsOrphan = false;           ///< Флаг "сироты": родитель завершился подозрительно быстро
    bool ParentIsSystem = false;     ///< Является ли родитель системным процессом (services.exe и т.д.)
    bool UncommonParent = false;     ///< Флаг нетипичной связи "Родитель-Ребенок"
    double ParentChildDistance = 0;  ///< Время в мс между запуском родителя и текущего процесса
    /// @}

    /// @name Динамические счетчики и уникальные элементы
    /// @{
    int EventCount = 0;                      ///< Общее количество событий, связанных с процессом
    std::set<std::wstring> UniqueDLLs;       ///< Список уникальных загруженных DLL (ID 7)
    std::set<std::wstring> TargetProcesses;  ///< Список процессов, к которым запрашивался доступ (ID 10)
    std::set<std::wstring> FileExtensions;   ///< Список расширений файлов, с которыми работал процесс
    /// @}

    /// @name Индикаторы аномального поведения (Триггеры)
    /// @{
    bool LsassAccessed = false;      ///< Флаг доступа к памяти процесса LSASS (LSASS_Access_Flag)
    int NetworkSuccessCount = 0;     ///< Количество успешных сетевых соединений
    int NetworkFailureCount = 0;     ///< Количество неудачных попыток соединения (Network_Success_Ratio)
    int DnsFailureCount = 0;         ///< Количество неудачных DNS запросов (DNS_Failed_Ratio)
    bool MassRenameDetected = false; ///< Флаг массового переименования файлов (признак шифровальщика)
    /// @}

    /// @name Временные ряды для нейросети
    /// @{
    std::vector<USHORT> Sequence;           ///< Последовательность ID событий (например: 1, 7, 3, 3, 5)
    std::vector<float> CpuUsageHistory;     ///< История потребления CPU (выборки по интервалам)
    std::vector<long long> EventTimestamps; ///< Временные метки событий для анализа частоты (Access_Frequency)
    /// @}

    /// @name Служебные поля
    /// @{
    std::wstring StartTime;          ///< Время запуска процесса (UtcTime из ID 1)
    std::wstring LastEventTime;      ///< Время последнего зафиксированного события
    /// @}
};

class ProcessTracker {
public:

    /**
    * @brief Первичная обработка приходяшего лога
    */
    void LogProcessing(const SysmonEvent& NewLog);

    void UpdateProcessNode(std::wstring& Name, SysmonEvent MyEvent);
    void AddNewProcessNode(std::wstring& currentGuid, SysmonEvent NewLog);
        

private:
    std::map<std::wstring, ProcessNode> _processes;
    std::mutex _mutex;
    PathNormalizer _normalizer;
};