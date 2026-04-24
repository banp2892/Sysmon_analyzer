#include "SysmonCollector.h"
#include <iostream>
#include <objbase.h>

#include <iomanip>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

SysmonCollector::SysmonCollector(const wchar_t* name, PreparationData* prep) : m_sessionName(name) {
    m_preparator = prep;
    std::wcout << L"[DEBUG] Инициализация SysmonCollector для сессии: " << m_sessionName << std::endl;

    SetupProperties();

    std::wcout << L"[DEBUG] Попытка остановки старой сессии (если была)... ";
    StopOldSession(); // Код не проверяем, так как сессии может не быть
    std::wcout << L"OK" << std::endl;

    std::wcout << L"[DEBUG] Запуск новой ETW сессии... ";
    StartSession();
    std::wcout << L"OK (Handle: " << m_sessionHandle << L")" << std::endl;

    std::wcout << L"[DEBUG] Подключение провайдера Sysmon... ";
    EnableSysmon();
    std::wcout << L"OK" << std::endl;
}

SysmonCollector::~SysmonCollector() {
    if (m_sessionHandle) {
        std::wcout << L"[DEBUG] Завершение работы. Остановка сессии... ";
        ControlTraceW(m_sessionHandle, m_sessionName.c_str(), (PEVENT_TRACE_PROPERTIES)m_propsBuffer.data(), EVENT_TRACE_CONTROL_STOP);
        std::wcout << L"Done." << std::endl;
    }
}

void SysmonCollector::Run() {
    std::wcout << L"[DEBUG] Настройка лог-файла в реальном времени..." << std::endl;
    EVENT_TRACE_LOGFILEW logFile = { 0 };
    logFile.LoggerName = (LPWSTR)m_sessionName.c_str();
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = SysmonCollector::OnEventRecord;

    m_traceHandle = OpenTraceW(&logFile);
    if (m_traceHandle == (TRACEHANDLE)INVALID_PROCESSTRACE_HANDLE) {
        std::wcerr << L"[ERROR] Не удалось открыть трассировку. Ошибка: " << GetLastError() << std::endl;
        return;
    }

    std::wcout << L"[SYSTEM] Служба IDS запущена. Ожидание событий Sysmon..." << std::endl;
    std::wcout << L"-------------------------------------------------------" << std::endl;

    ULONG status = ProcessTrace(&m_traceHandle, 1, NULL, NULL);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"[ERROR] Ошибка в цикле обработки событий: " << status << std::endl;
    }
}

void SysmonCollector::SetupProperties() {
    ULONG size = sizeof(EVENT_TRACE_PROPERTIES) + (2 * MAX_PATH * sizeof(WCHAR));
    m_propsBuffer.assign(size, 0);
    auto p = (EVENT_TRACE_PROPERTIES*)m_propsBuffer.data();
    p->Wnode.BufferSize = size;
    p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    wcscpy_s((wchar_t*)(m_propsBuffer.data() + p->LoggerNameOffset), MAX_PATH, m_sessionName.c_str());
}

void SysmonCollector::StopOldSession() {
    ControlTraceW(0, m_sessionName.c_str(), (PEVENT_TRACE_PROPERTIES)m_propsBuffer.data(), EVENT_TRACE_CONTROL_STOP);
}

void SysmonCollector::StartSession() {
    ULONG status = StartTraceW(&m_sessionHandle, m_sessionName.c_str(), (PEVENT_TRACE_PROPERTIES)m_propsBuffer.data());
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"\n[FATAL] Не удалось запустить сессию ETW. Код: " << status << std::endl;
        if (status == ERROR_ACCESS_DENIED) std::wcerr << L"СОВЕТ: Запусти Visual Studio от имени Администратора!" << std::endl;
        exit(status);
    }
}

void SysmonCollector::EnableSysmon() {
    // Microsoft-Windows-Sysmon {5770385F-C22A-43E0-BF4C-06F5698FFBD9}
    static const GUID sysmonGuid =
    { 0x5770385f, 0xc22a, 0x43e0, { 0xbf, 0x4c, 0x06, 0xf5, 0x69, 0x8f, 0xfb, 0xd9 } };
    ULONG status = EnableTraceEx2(m_sessionHandle, &sysmonGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"\n[ERROR] Не удалось подключить Sysmon провайдер. Код: " << status << std::endl;
    }
}

void SysmonCollector::ParseAndLog(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo) {
    USHORT eventId = pEvent->EventHeader.EventDescriptor.Id;

    switch (eventId) {
    case 1: { // Создание процесса
        ID_1_SYSMONEVENT_CREATE_PROCESS pd;
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.CommandLine = GetEventProperty(pEvent, pInfo, L"CommandLine");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.ProcessGuid = GetEventProperty(pEvent, pInfo, L"ProcessGuid");
        pd.User = GetEventProperty(pEvent, pInfo, L"User");

        if (m_preparator) m_preparator->PrepareProcess(pd);

        std::wcout << L"[PROC] PID: " << pd.ProcessId << L" | Path: " << pd.Image << std::endl;
        break;
    }

    case 3: { // Сетевое соединение
        ID_3_SYSMONEVENT_NETWORK_CONNECT nd;
        nd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        nd.DestinationIp = GetEventProperty(pEvent, pInfo, L"DestinationIp");
        nd.DestinationPort = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"DestinationPort"));
        nd.Protocol = GetEventProperty(pEvent, pInfo, L"Protocol");

        std::wcout << L"[NET] " << nd.Image << L" -> " << nd.DestinationIp << L":" << nd.DestinationPort << std::endl;
        break;
    }

    case 7: { // Загрузка модуля (DLL) - Твой новый "спам"
        ID_7_SYSMONEVENT_IMAGE_LOAD ild;
        ild.Image = GetEventProperty(pEvent, pInfo, L"Image");
        ild.ImageLoaded = GetEventProperty(pEvent, pInfo, L"ImageLoaded"); // Путь к DLL
        ild.Signed = GetEventProperty(pEvent, pInfo, L"Signed");
        ild.Signature = GetEventProperty(pEvent, pInfo, L"Signature");
        ild.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));

        std::wcout << L"[DLL] Proc: " << ild.Image << L" LOADED: " << ild.ImageLoaded
            << L" [Signed: " << ild.Signed << L"]" << std::endl;
        break;
    }

    case 10: { // Process Access
        ID_10_SYSMONEVENT_ACCESS_PROCESS apd;
        apd.SourceImage = GetEventProperty(pEvent, pInfo, L"SourceImage");
        apd.TargetImage = GetEventProperty(pEvent, pInfo, L"TargetImage");

        // ВНИМАНИЕ: Обязательно передаем аргументы!
        apd.GrantedAccess = GetEventPropertyInt(pEvent, L"GrantedAccess");

        std::wcout << L"!!!!!!!![ACCESS] Src: " << apd.SourceImage
            << L" -> Tgt: " << apd.TargetImage
            << L" | Access: 0x" << std::hex << std::setw(8) << std::setfill(L'0')
            << apd.GrantedAccess << std::dec << std::endl;
        break;
    }

    case 22: { // DNS Запрос
        ID_22_SYSMONEVENT_DNS_QUERY dqd;
        dqd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        dqd.QueryName = GetEventProperty(pEvent, pInfo, L"QueryName"); // Домен
        dqd.QueryResults = GetEventProperty(pEvent, pInfo, L"QueryResults"); // IP адреса
        dqd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));

        std::wcout << L"[DNS] " << dqd.Image << L" queried " << dqd.QueryName
            << L" Result: " << dqd.QueryResults << std::endl;
        break;
    }

    default:
        // Для отладки остальных ID, которые мы пока не расписали
        // std::wcout << L"[DEBUG] Unhandled Event ID: " << eventId << std::endl;
        break;
    }
}

std::wstring SysmonCollector::GetEventProperty(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, const wchar_t* name) {
    PROPERTY_DATA_DESCRIPTOR desc = { (ULONGLONG)name, 0 };
    DWORD size = 0;
    TdhGetPropertySize(pEvent, 0, NULL, 1, &desc, &size);
    if (size == 0) return L"";
    std::vector<BYTE> buf(size);
    TdhGetProperty(pEvent, 0, NULL, 1, &desc, size, buf.data());
    return std::wstring((wchar_t*)buf.data());
}

DWORD SysmonCollector::GetEventPropertyInt(PEVENT_RECORD pEvent, const wchar_t* name) {
    PROPERTY_DATA_DESCRIPTOR desc = { (ULONGLONG)name, 0 };
    DWORD size = 0;

    // Проверка размера обязательна
    if (TdhGetPropertySize(pEvent, 0, NULL, 1, &desc, &size) != ERROR_SUCCESS || size == 0) {
        return 0;
    }

    DWORD val = 0;
    // Напрямую читаем в DWORD. Если данных меньше 4 байт, val заполнится частично.
    // Если больше — возьмем первые 4.
    TdhGetProperty(pEvent, 0, NULL, 1, &desc, (size > 4) ? 4 : size, (PBYTE)&val);

    return val;
}

std::wstring SysmonCollector::GetGuidProperty(PEVENT_RECORD pEvent, const wchar_t* name) {
    PROPERTY_DATA_DESCRIPTOR desc = { (ULONGLONG)name, 0 };
    DWORD size = 0;
    // 1. Узнаем размер
    if (TdhGetPropertySize(pEvent, 0, NULL, 1, &desc, &size) != ERROR_SUCCESS) {
        return L"";
    }
    std::vector<BYTE> buf(size);
    if (TdhGetProperty(pEvent, 0, NULL, 1, &desc, size, buf.data()) != ERROR_SUCCESS) {
        return L"";
    }
    // 2. Если размер 16 байт — это бинарный GUID (структура)
    if (size == sizeof(GUID)) {
        GUID* g = (GUID*)buf.data();
        wchar_t szGuid[40]; // Буфер для строки GUID
        if (StringFromGUID2(*g, szGuid, ARRAYSIZE(szGuid)) != 0) {
            return std::wstring(szGuid);
        }
    }
    // 3. Если это уже строка (Unicode)
    if (size >= sizeof(wchar_t)) {
        // Указываем размер явно, чтобы не зависеть от нулевого терминатора
        return std::wstring((wchar_t*)buf.data(), size / sizeof(wchar_t)).c_str();
    }
    return L"";
}


void WINAPI SysmonCollector::OnEventRecord(PEVENT_RECORD pEvent) {

    std::wcout << L"!" << std::flush;
    DWORD size = 0;
    if (TdhGetEventInformation(pEvent, 0, NULL, NULL, &size) == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<BYTE> info(size);
        auto pInfo = (PTRACE_EVENT_INFO)info.data();
        if (TdhGetEventInformation(pEvent, 0, NULL, pInfo, &size) == ERROR_SUCCESS) {
            ParseAndLog(pEvent, pInfo);
        }
    }
}