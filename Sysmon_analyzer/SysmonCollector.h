#pragma once
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <vector>
#include <string>
#include "EventFeature.h"

/**
 * @class SysmonCollector
 * @brief Класс для управления сессией трассировки событий Windows (ETW) и сбора данных из Sysmon.
 * * Реализует паттерн RAII: инициализирует сессию при создании и гарантированно
 * завершает её при уничтожении объекта.
 */
class SysmonCollector {
private:
    TRACEHANDLE m_sessionHandle = 0; ///< Хэндл сессии трассировки
    TRACEHANDLE m_traceHandle = 0;   ///< Хэндл открытого лога (потребителя)
    std::wstring m_sessionName;      ///< Имя сессии трассировки
    std::vector<unsigned char> m_propsBuffer; ///< Буфер для свойств сессии

public:
    /**
     * @brief Конструктор: подготавливает и запускает сессию Sysmon.
     * @param name Имя сессии трассировки.
     */
    SysmonCollector(const wchar_t* name);

    /**
     * @brief Деструктор: останавливает сессию трассировки и освобождает ресурсы.
     */
    ~SysmonCollector();

    /**
     * @brief Запускает цикл обработки событий в реальном времени.
     * @note Метод является блокирующим до момента остановки трассировки.
     */
    void Run();

private:
    /**
     * @brief Инициализирует структуру EVENT_TRACE_PROPERTIES в буфере.
     */
    void SetupProperties();

    /**
     * @brief Останавливает существующую сессию с тем же именем, если она зависла в системе.
     */
    void StopOldSession();

    /**
     * @brief Регистрирует и запускает новую сессию трассировки в ядре Windows.
     */
    void StartSession();

    /**
     * @brief Подключает провайдер Microsoft-Windows-Sysmon к созданной сессии.
     */
    void EnableSysmon();

    /**
     * @brief Статический обратный вызов (Callback), вызываемый Windows при поступлении каждого события.
     * @param pEvent Указатель на структуру события.
     */
    static void WINAPI OnEventRecord(PEVENT_RECORD pEvent);

    /**
     * @brief Выполняет высокоуровневую фильтрацию и логирование событий на основе их Event ID.
     * @param pEvent Указатель на заголовок события.
     * @param pInfo Указатель на метаданные (схему) события.
     */
    static void ParseAndLog(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo);

    /**
     * @brief Извлекает строковое свойство из данных события.
     * @param pEvent Запись события.
     * @param pInfo Метаданные события.
     * @param name Имя запрашиваемого свойства (напр. L"Image").
     * @return Строка (std::wstring) со значением свойства.
     */
    static std::wstring GetEventProperty(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, const wchar_t* name);

    /**
     * @brief Извлекает целочисленное (DWORD) свойство из данных события.
     * @param pEvent Запись события.
     * @param name Имя запрашиваемого свойства (напр. L"DestinationPort").
     * @return Числовое значение свойства.
     */
    static DWORD GetEventPropertyInt(PEVENT_RECORD pEvent, const wchar_t* name);
};