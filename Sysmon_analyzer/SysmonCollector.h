#pragma once
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <vector>
#include <iostream>
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
    SysmonCollector(const wchar_t* name) : m_sessionName(name) {
        SetupProperties();
        StopOldSession();
        StartSession();
        EnableSysmon();
    }

    /**
     * @brief Деструктор: останавливает сессию трассировки и освобождает ресурсы.
     */
    ~SysmonCollector() {
        if (m_sessionHandle) {
            ControlTraceW(m_sessionHandle, m_sessionName.c_str(), (PEVENT_TRACE_PROPERTIES)m_propsBuffer.data(), EVENT_TRACE_CONTROL_STOP);
        }
    }

    /**
     * @brief Запускает цикл обработки событий в реальном времени.
     * @note Метод является блокирующим до момента остановки трассировки.
     */
    void Run() {
        EVENT_TRACE_LOGFILEW logFile = { 0 };
        logFile.LoggerName = (LPWSTR)m_sessionName.c_str();
        logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logFile.EventRecordCallback = SysmonCollector::OnEventRecord;

        m_traceHandle = OpenTraceW(&logFile);
        if (m_traceHandle != (TRACEHANDLE)INVALID_PROCESSTRACE_HANDLE) {
            ProcessTrace(&m_traceHandle, 1, NULL, NULL);
        }
    }

private:
    /**
     * @brief Инициализирует структуру EVENT_TRACE_PROPERTIES в буфере.
     */
    void SetupProperties() {
        ULONG size = sizeof(EVENT_TRACE_PROPERTIES) + (2 * MAX_PATH * sizeof(WCHAR));
        m_propsBuffer.assign(size, 0);
        auto p = (EVENT_TRACE_PROPERTIES*)m_propsBuffer.data();
        p->Wnode.BufferSize = size;
        p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        wcscpy_s((wchar_t*)(m_propsBuffer.data() + p->LoggerNameOffset), MAX_PATH, m_sessionName.c_str());
    }

    /**
     * @brief Останавливает существующую сессию с тем же именем, если она зависла в системе.
     */
    void StopOldSession() {
        ControlTraceW(0, m_sessionName.c_str(), (PEVENT_TRACE_PROPERTIES)m_propsBuffer.data(), EVENT_TRACE_CONTROL_STOP);
    }

    /**
     * @brief Регистрирует и запускает новую сессию трассировки в ядре Windows.
     */
    void StartSession() {
        StartTraceW(&m_sessionHandle, m_sessionName.c_str(), (PEVENT_TRACE_PROPERTIES)m_propsBuffer.data());
    }

    /**
     * @brief Подключает провайдер Microsoft-Windows-Sysmon к созданной сессии.
     */
    void EnableSysmon() {
        static const GUID sysmonGuid = { 0x5770385f, 0xc22a, 0x43e0, { 0xbf, 0x4c, 0x06, 0xf5, 0x69, 0x8f, 0xfb, 0xd9 } };
        EnableTraceEx2(m_sessionHandle, &sysmonGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
    }

    /**
     * @brief Статический обратный вызов (Callback), вызываемый Windows при поступлении каждого события.
     * @param pEvent Указатель на структуру события.
     */
    static void WINAPI OnEventRecord(PEVENT_RECORD pEvent) {
        DWORD size = 0;
        if (TdhGetEventInformation(pEvent, 0, NULL, NULL, &size) == ERROR_INSUFFICIENT_BUFFER) {
            std::vector<BYTE> info(size);
            auto pInfo = (PTRACE_EVENT_INFO)info.data();
            if (TdhGetEventInformation(pEvent, 0, NULL, pInfo, &size) == ERROR_SUCCESS) {
                ParseAndLog(pEvent, pInfo);
            }
        }
    }

    /**
     * @brief Выполняет высокоуровневую фильтрацию и логирование событий на основе их Event ID.
     * @param pEvent Указатель на заголовок события.
     * @param pInfo Указатель на метаданные (схему) события.
     */
    static void ParseAndLog(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo) {
        switch (pEvent->EventHeader.EventDescriptor.Id) {
        case 3: { // Network connection
            std::wstring path = GetEventProperty(pEvent, pInfo, L"Image");
            DWORD port = GetEventPropertyInt(pEvent, L"DestinationPort");
            std::wcout << L"[NET] " << path << L" Port: " << port << std::endl;
            break;
        }
        case 1: { // Process creation
            std::wstring cmd = GetEventProperty(pEvent, pInfo, L"CommandLine");
            double ent = EventFeature::CalculateEntropy(cmd);
            std::wcout << L"[PROC] Entropy: " << ent << L" CMD: " << cmd << std::endl;
            break;
        }
        }
    }

    /**
     * @brief Извлекает строковое свойство из данных события.
     * @param pEvent Запись события.
     * @param pInfo Метаданные события.
     * @param name Имя запрашиваемого свойства (напр. L"Image").
     * @return Строка (std::wstring) со значением свойства.
     */
    static std::wstring GetEventProperty(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, const wchar_t* name) {
        PROPERTY_DATA_DESCRIPTOR desc = { (ULONGLONG)name, 0 };
        DWORD size = 0;
        TdhGetPropertySize(pEvent, 0, NULL, 1, &desc, &size);
        std::vector<BYTE> buf(size);
        TdhGetProperty(pEvent, 0, NULL, 1, &desc, size, buf.data());
        return std::wstring((wchar_t*)buf.data());
    }

    /**
     * @brief Извлекает целочисленное (DWORD) свойство из данных события.
     * @param pEvent Запись события.
     * @param name Имя запрашиваемого свойства (напр. L"DestinationPort").
     * @return Числовое значение свойства.
     */
    static DWORD GetEventPropertyInt(PEVENT_RECORD pEvent, const wchar_t* name) {
        PROPERTY_DATA_DESCRIPTOR desc = { (ULONGLONG)name, 0 };
        DWORD val = 0;
        TdhGetProperty(pEvent, 0, NULL, 1, &desc, sizeof(DWORD), (PBYTE)&val);
        return val;
    }
};