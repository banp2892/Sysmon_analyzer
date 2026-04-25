#include "SysmonCollector.h"
#include <iostream>
#include <objbase.h>

#include <iomanip>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

#include <sstream>
#include <chrono>

long long UtcTimeToLong(const std::wstring& utcStr) {
    std::wstringstream ss(utcStr);
    std::tm tm = {};
    wchar_t discard;
    int milliseconds = 0;

    ss >> std::get_time(&tm, L"%Y-%m-%d %H:%M:%S");
    ss >> discard >> milliseconds;
    std::time_t seconds = _mkgmtime(&tm);
    return (static_cast<long long>(seconds) * 1000) + milliseconds;
}

SysmonCollector::SysmonCollector(const wchar_t* name) : m_sessionName(name) {
    std::wcout << L"[DEBUG] Инициализация SysmonCollector для сессии: " << m_sessionName << std::endl;

    SetupProperties();

    std::wcout << L"[DEBUG] Попытка остановки старой сессии (если была)... ";
    StopOldSession();
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
   case 1: { // Process Creation
        ID_1_SYSMONEVENT_CREATE_PROCESS pd;
        
        // Извлекаем основные свойства
        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.CommandLine = GetEventProperty(pEvent, pInfo, L"CommandLine");
        
        // КРИТИЧНО: Извлекаем GUID и ParentGuid для построения дерева процессов
        pd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        pd.ParentProcessGuid = GetGuidProperty(pEvent, L"ParentProcessGuid");
        pd.ParentProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ParentProcessId"));

        // Подготавливаем общий контейнер события
        SysmonEvent temp_SE;
        temp_SE.eventId = eventId;
        temp_SE.timestamp_wstring = pd.UtcTime;
        temp_SE.timestamp = UtcTimeToLong(pd.UtcTime);
        
        // Упаковываем структуру конкретного события в variant
        temp_SE.eventData = pd;

        // Отправляем на обработку в трекер (через статическую переменную m_tracker)


        /*std::wcout << L"[" << pd.UtcTime << L"] [ID: 1] [PROC_CREATE] PID: " << pd.ProcessId
             << L" | GUID: " << pd.ProcessGuid << std::endl
             << L"   > Image: " << pd.Image << std::endl;*/

        break;
    }

    case 2: { // File Modification Time
        ID_2_SYSMONEVENT_FILE_TIME fd;
        fd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        fd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        fd.TargetFilename = GetEventProperty(pEvent, pInfo, L"TargetFilename");

        std::wcout << L"[" << fd.UtcTime << L"] [ID: 2] [FILE_TIME] Proc: " << fd.Image
            << L" changed time of: " << fd.TargetFilename << std::endl;
        break;
    }

    case 3: { // Network Connection
        ID_3_SYSMONEVENT_NETWORK_CONNECT nd;
        nd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        nd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        nd.DestinationIp = GetEventProperty(pEvent, pInfo, L"DestinationIp");
        nd.DestinationPort = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"DestinationPort"));
        nd.Protocol = GetEventProperty(pEvent, pInfo, L"Protocol");

        std::wcout << L"[" << nd.UtcTime << L"] [ID: 3] [NET] " << nd.Image
            << L" -> " << nd.DestinationIp << L":" << nd.DestinationPort << L" (" << nd.Protocol << L")" << std::endl;
        break;
    }

    case 5: { // Process Terminated
        ID_5_SYSMONEVENT_PROCESS_TERMINATE td;
        td.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        td.Image = GetEventProperty(pEvent, pInfo, L"Image");
        td.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));

        std::wcout << L"[" << td.UtcTime << L"] [ID: 5] [PROC_TERM] PID: " << td.ProcessId << L" Image: " << td.Image << std::endl;
        break;
    }

    case 6: { // Driver Load
        ID_6_SYSMONEVENT_DRIVER_LOAD drd;
        drd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        drd.ImageLoaded = GetEventProperty(pEvent, pInfo, L"ImageLoaded");
        drd.Signature = GetEventProperty(pEvent, pInfo, L"Signature");

        std::wcout << L"[" << drd.UtcTime << L"] [ID: 6] [DRIVER] LOADED: " << drd.ImageLoaded
            << L" | Sign: " << drd.Signature << std::endl;
        break;
    }

    case 7: { // Image Load (DLL)
        ID_7_SYSMONEVENT_IMAGE_LOAD ild;
        ild.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        ild.Image = GetEventProperty(pEvent, pInfo, L"Image");
        ild.ImageLoaded = GetEventProperty(pEvent, pInfo, L"ImageLoaded");

        std::wcout << L"[" << ild.UtcTime << L"] [ID: 7] [DLL_LOAD] Proc: " << ild.Image
            << L" loaded " << ild.ImageLoaded << std::endl;
        break;
    }

    case 8: { // Create Remote Thread
        ID_8_SYSMONEVENT_CREATE_REMOTE_THREAD rtd;
        rtd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        rtd.SourceImage = GetEventProperty(pEvent, pInfo, L"SourceImage");
        rtd.TargetImage = GetEventProperty(pEvent, pInfo, L"TargetImage");
        rtd.StartFunction = GetEventProperty(pEvent, pInfo, L"StartFunction");

        std::wcout << L"[" << rtd.UtcTime << L"] [ID: 8] [REMOTE_THREAD] ALERT! Src: " << rtd.SourceImage
            << L" -> Tgt: " << rtd.TargetImage << L" | Func: " << rtd.StartFunction << std::endl;
        break;
    }

    case 9: { // Raw Access Read
        ID_9_SYSMONEVENT_RAWACCESS_READ rad;
        rad.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        rad.Image = GetEventProperty(pEvent, pInfo, L"Image");
        rad.Device = GetEventProperty(pEvent, pInfo, L"Device");

        std::wcout << L"[" << rad.UtcTime << L"] [ID: 9] [RAW_READ] Proc: " << rad.Image << L" accessed " << rad.Device << std::endl;
        break;
    }

    case 10: { // Process Access
        ID_10_SYSMONEVENT_ACCESS_PROCESS apd;
        apd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        apd.SourceImage = GetEventProperty(pEvent, pInfo, L"SourceImage");
        apd.TargetImage = GetEventProperty(pEvent, pInfo, L"TargetImage");

        // Используем твою новую функцию
        DWORD accessMask = GetEventPropertyInt(pEvent, L"GrantedAccess");

        std::wcout << L"[" << apd.UtcTime << L"] [ID:10] [PROC_ACCESS] "
            << L"Src: " << (apd.SourceImage.empty() ? L"Unknown" : apd.SourceImage)
            << L" -> Tgt: " << (apd.TargetImage.empty() ? L"Unknown" : apd.TargetImage)
            << L" | Mask: 0x" << std::hex << std::setw(8) << std::setfill(L'0') << accessMask
            << std::dec << std::endl;
        break;
    }

    case 11: { // File Create
        ID_11_SYSMONEVENT_FILE_CREATE fcd;
        fcd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        fcd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        fcd.TargetFilename = GetEventProperty(pEvent, pInfo, L"TargetFilename");

        std::wcout << L"[" << fcd.UtcTime << L"] [ID:11] [FILE_CREATE] Proc: " << fcd.Image << L" created: " << fcd.TargetFilename << std::endl;
        break;
    }

    case 12: case 13: case 14: { // Registry Events
        std::wstring eType = GetEventProperty(pEvent, pInfo, L"EventType");
        std::wstring utctime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        std::wstring img = GetEventProperty(pEvent, pInfo, L"Image");
        std::wstring obj = GetEventProperty(pEvent, pInfo, L"TargetObject");

        std::wcout << L"[" << utctime << L"] [ID:" << eventId << L"] [REGISTRY] " << eType
            << L" | Proc: " << img << L" | Obj: " << obj << std::endl;
        break;
    }

    case 17: case 18: { // Named Pipes
        std::wstring pName = GetEventProperty(pEvent, pInfo, L"PipeName");
        std::wstring utctime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        std::wstring img = GetEventProperty(pEvent, pInfo, L"Image");

        std::wcout << L"[" << utctime << L"] [ID:" << eventId << L"] [PIPE] Proc: " << img
            << (eventId == 17 ? L" CREATED pipe: " : L" CONNECTED to pipe: ") << pName << std::endl;
        break;
    }

    case 22: { // DNS Query
        ID_22_SYSMONEVENT_DNS_QUERY dqd;
        dqd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        dqd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        dqd.QueryName = GetEventProperty(pEvent, pInfo, L"QueryName");
        dqd.QueryResults = GetEventProperty(pEvent, pInfo, L"QueryResults");

        std::wcout << L"[" << dqd.UtcTime << L"] [ID:22] [DNS] " << dqd.Image
            << L" queried " << dqd.QueryName << L" -> " << dqd.QueryResults << std::endl;
        break;
    }

    case 23: case 26: { // File Delete
        std::wstring utctime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        std::wstring img = GetEventProperty(pEvent, pInfo, L"Image");
        std::wstring target = GetEventProperty(pEvent, pInfo, L"TargetFilename");

        std::wcout << L"[" << utctime << L"] [ID:" << eventId << L"] [FILE_DELETE] Proc: " << img << L" deleted: " << target << std::endl;
        break;
    }

    case 25: { // Process Tampering
        ID_25_SYSMONEVENT_PROCESS_IMAGE_TAMPERING ptd;
        ptd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        ptd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        ptd.Type = GetEventProperty(pEvent, pInfo, L"Type");

        std::wcout << L"[" << ptd.UtcTime << L"] [ID:25] [TAMPERING] ALERT! Proc: " << ptd.Image << L" Type: " << ptd.Type << std::endl;
        break;
    }

    case 29: { // New Executable Detected
        ID_29_SYSMONEVENT_FILE_EXE_DETECTED ed;
        ed.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        ed.Image = GetEventProperty(pEvent, pInfo, L"Image");
        ed.TargetFilename = GetEventProperty(pEvent, pInfo, L"TargetFilename");

        std::wcout << L"[" << ed.UtcTime << L"] [ID:29] [NEW_EXE] WARNING! Proc: " << ed.Image
            << L" dropped EXE: " << ed.TargetFilename << std::endl;
        break;
    }

    default:
        std::wcout << L"[" << GetEventProperty(pEvent, pInfo, L"UtcTime") << L"] [ID:" << eventId << L"] Generic Event detected." << std::endl;
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