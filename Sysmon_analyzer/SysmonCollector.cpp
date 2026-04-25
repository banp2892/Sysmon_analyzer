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
        
        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.CommandLine = GetEventProperty(pEvent, pInfo, L"CommandLine");

        pd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        pd.ParentProcessGuid = GetGuidProperty(pEvent, L"ParentProcessGuid");
        pd.ParentProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ParentProcessId"));

        SysmonEvent temp_SE;
        temp_SE.eventId = eventId;
        temp_SE.timestamp_wstring = pd.UtcTime;
        temp_SE.timestamp = UtcTimeToLong(pd.UtcTime);

        temp_SE.eventData = pd;

        myTracker.LogProcessing(temp_SE);

        /*std::wcout << L"[" << pd.UtcTime << L"] [ID: 1] [PROC_CREATE] PID: " << pd.ProcessId
             << L" | GUID: " << pd.ProcessGuid << std::endl
             << L"   > Image: " << pd.Image << std::endl;*/

        break;
    }

   case 2: { // File Modification Time (Change of file creation time)
       ID_2_SYSMONEVENT_FILE_TIME fd;

       // Извлекаем свойства
       fd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
       fd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
       fd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
       fd.Image = GetEventProperty(pEvent, pInfo, L"Image");
       fd.TargetFilename = GetEventProperty(pEvent, pInfo, L"TargetFilename");
       fd.CreationUtcTime = GetEventProperty(pEvent, pInfo, L"CreationUtcTime");
       fd.PreviousCreationUtcTime = GetEventProperty(pEvent, pInfo, L"PreviousCreationUtcTime");

       // Подготавливаем контейнер
       SysmonEvent temp_SE;
       temp_SE.eventId = eventId;
       temp_SE.timestamp_wstring = fd.UtcTime;
       temp_SE.timestamp = UtcTimeToLong(fd.UtcTime);
       temp_SE.eventData = fd;

       myTracker.LogProcessing(temp_SE);
       break;
   }

   case 3: { // Network Connection
       ID_3_SYSMONEVENT_NETWORK_CONNECT nd;

       nd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
       nd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
       nd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
       nd.Image = GetEventProperty(pEvent, pInfo, L"Image");
       nd.User = GetEventProperty(pEvent, pInfo, L"User");
       nd.Protocol = GetEventProperty(pEvent, pInfo, L"Protocol");
       nd.Initiated = (GetEventProperty(pEvent, pInfo, L"Initiated") == L"true");
       nd.SourceIsIpv6 = (GetEventProperty(pEvent, pInfo, L"SourceIsIpv6") == L"true");
       nd.SourceIp = GetEventProperty(pEvent, pInfo, L"SourceIp");
       nd.SourceHostname = GetEventProperty(pEvent, pInfo, L"SourceHostname");
       nd.SourcePort = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"SourcePort"));
       nd.DestinationIp = GetEventProperty(pEvent, pInfo, L"DestinationIp");
       nd.DestinationHostname = GetEventProperty(pEvent, pInfo, L"DestinationHostname");
       nd.DestinationPort = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"DestinationPort"));

       SysmonEvent temp_SE;
       temp_SE.eventId = eventId;
       temp_SE.timestamp_wstring = nd.UtcTime;
       temp_SE.timestamp = UtcTimeToLong(nd.UtcTime);
       temp_SE.eventData = nd;

       myTracker.LogProcessing(temp_SE);
       break;
   }

   case 4: { // Sysmon Service State Change
       ID_4_SYSMONEVENT_SERVICE_STATE_CHANGE sd;

       // Извлекаем свойства
       sd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
       sd.State = GetEventProperty(pEvent, pInfo, L"State");
       sd.Version = GetEventProperty(pEvent, pInfo, L"Version");
       sd.SchemaVersion = GetEventProperty(pEvent, pInfo, L"SchemaVersion");

       // Подготавливаем контейнер
       SysmonEvent temp_SE;
       temp_SE.eventId = eventId;
       temp_SE.timestamp_wstring = sd.UtcTime;
       temp_SE.timestamp = UtcTimeToLong(sd.UtcTime);
       temp_SE.eventData = sd;

       myTracker.LogProcessing(temp_SE);
       break;
   }

   case 5: { // Process Terminated
       ID_5_SYSMONEVENT_PROCESS_TERMINATE td;

       // Извлекаем свойства
       td.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
       td.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
       td.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
       td.Image = GetEventProperty(pEvent, pInfo, L"Image");

       // Подготавливаем контейнер
       SysmonEvent temp_SE;
       temp_SE.eventId = eventId;
       temp_SE.timestamp_wstring = td.UtcTime;
       temp_SE.timestamp = UtcTimeToLong(td.UtcTime);
       temp_SE.eventData = td;

       // Отправляем в трекер (здесь должна быть логика удаления из активной мапы)
       myTracker.LogProcessing(temp_SE);
       break;
   }

    case 6: { // Driver Load
        ID_6_SYSMONEVENT_DRIVER_LOAD drd;

        // Извлекаем свойства
        drd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        drd.ImageLoaded = GetEventProperty(pEvent, pInfo, L"ImageLoaded");
        drd.Hashes = GetEventProperty(pEvent, pInfo, L"Hashes");
        drd.Signed = (GetEventProperty(pEvent, pInfo, L"Signed") == L"true");
        drd.Signature = GetEventProperty(pEvent, pInfo, L"Signature");
        drd.SignatureStatus = GetEventProperty(pEvent, pInfo, L"SignatureStatus");

        // Подготавливаем контейнер
        SysmonEvent temp_SE;
        temp_SE.eventId = eventId;
        temp_SE.timestamp_wstring = drd.UtcTime;
        temp_SE.timestamp = UtcTimeToLong(drd.UtcTime);
        temp_SE.eventData = drd;

        myTracker.LogProcessing(temp_SE);
        break;
    }
    case 7: { // Image Load (DLL Loaded)
        ID_7_SYSMONEVENT_IMAGE_LOAD ild;

        ild.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        ild.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        ild.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        ild.Image = GetEventProperty(pEvent, pInfo, L"Image");
        ild.ImageLoaded = GetEventProperty(pEvent, pInfo, L"ImageLoaded");
        ild.FileVersion = GetEventProperty(pEvent, pInfo, L"FileVersion");
        ild.Description = GetEventProperty(pEvent, pInfo, L"Description");
        ild.Product = GetEventProperty(pEvent, pInfo, L"Product");
        ild.Company = GetEventProperty(pEvent, pInfo, L"Company");
        ild.Hashes = GetEventProperty(pEvent, pInfo, L"Hashes");
        ild.Signed = (GetEventProperty(pEvent, pInfo, L"Signed") == L"true");
        ild.Signature = GetEventProperty(pEvent, pInfo, L"Signature");
        ild.SignatureStatus = GetEventProperty(pEvent, pInfo, L"SignatureStatus");

        SysmonEvent temp_SE;
        temp_SE.eventId = eventId;
        temp_SE.timestamp_wstring = ild.UtcTime;
        temp_SE.timestamp = UtcTimeToLong(ild.UtcTime);
        temp_SE.eventData = ild;

        myTracker.LogProcessing(temp_SE);
        break;
    }

    case 8: { // Create Remote Thread (Часто инъекция кода)
        ID_8_SYSMONEVENT_CREATE_REMOTE_THREAD rtd;

        rtd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        rtd.SourceProcessGuid = GetGuidProperty(pEvent, L"SourceProcessGuid");
        rtd.SourceProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"SourceProcessId"));
        rtd.SourceImage = GetEventProperty(pEvent, pInfo, L"SourceImage");
        rtd.TargetProcessGuid = GetGuidProperty(pEvent, L"TargetProcessGuid");
        rtd.TargetProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"TargetProcessId"));
        rtd.TargetImage = GetEventProperty(pEvent, pInfo, L"TargetImage");
        rtd.NewThreadId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"NewThreadId"));
        rtd.StartAddress = GetEventProperty(pEvent, pInfo, L"StartAddress");
        rtd.StartModule = GetEventProperty(pEvent, pInfo, L"StartModule");
        rtd.StartFunction = GetEventProperty(pEvent, pInfo, L"StartFunction");

        SysmonEvent temp_SE;
        temp_SE.eventId = eventId;
        temp_SE.timestamp_wstring = rtd.UtcTime;
        temp_SE.timestamp = UtcTimeToLong(rtd.UtcTime);
        temp_SE.eventData = rtd;

        myTracker.LogProcessing(temp_SE);
        break;
    }

    case 9: { // Raw Access Read (Чтение диска в обход ФС, часто — дамперы памяти)
        ID_9_SYSMONEVENT_RAWACCESS_READ rad;

        rad.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        rad.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        rad.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        rad.Image = GetEventProperty(pEvent, pInfo, L"Image");
        rad.Device = GetEventProperty(pEvent, pInfo, L"Device");

        SysmonEvent temp_SE;
        temp_SE.eventId = eventId;
        temp_SE.timestamp_wstring = rad.UtcTime;
        temp_SE.timestamp = UtcTimeToLong(rad.UtcTime);
        temp_SE.eventData = rad;

        myTracker.LogProcessing(temp_SE);
        break;
    }

    

    case 10: { // Process Access (Handle opening)
    ID_10_SYSMONEVENT_ACCESS_PROCESS apd;

    apd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
    apd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
    apd.SourceProcessGUID = GetGuidProperty(pEvent, L"SourceProcessGUID");
    apd.SourceProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"SourceProcessId"));
    apd.SourceThreadId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"SourceThreadId"));
    apd.SourceImage = GetEventProperty(pEvent, pInfo, L"SourceImage");
    apd.TargetProcessGUID = GetGuidProperty(pEvent, L"TargetProcessGUID");
    apd.TargetProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"TargetProcessId"));
    apd.TargetImage = GetEventProperty(pEvent, pInfo, L"TargetImage");
    apd.GrantedAccess = GetEventProperty(pEvent, pInfo, L"GrantedAccess"); // Тут wstring
    apd.CallTrace = GetEventProperty(pEvent, pInfo, L"CallTrace");
    apd.SourceUser = GetEventProperty(pEvent, pInfo, L"SourceUser");
    apd.TargetUser = GetEventProperty(pEvent, pInfo, L"TargetUser");

    SysmonEvent temp_SE;
    temp_SE.eventId = eventId;
    temp_SE.timestamp_wstring = apd.UtcTime;
    temp_SE.timestamp = UtcTimeToLong(apd.UtcTime);
    temp_SE.eventData = apd;

    myTracker.LogProcessing(temp_SE);
    break;
}

    case 11: { // File Create
        ID_11_SYSMONEVENT_FILE_CREATE fcd;

        fcd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        fcd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        fcd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        fcd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        fcd.TargetFilename = GetEventProperty(pEvent, pInfo, L"TargetFilename");
        fcd.CreationUtcTime = GetEventProperty(pEvent, pInfo, L"CreationUtcTime");

        SysmonEvent temp_SE;
        temp_SE.eventId = eventId;
        temp_SE.timestamp_wstring = fcd.UtcTime;
        temp_SE.timestamp = UtcTimeToLong(fcd.UtcTime);
        temp_SE.eventData = fcd;

        myTracker.LogProcessing(temp_SE);
        break;
    }

    case 12: { // Registry Event (Object create and delete)
        ID_12_SYSMONEVENT_REG_KEY rd;

        rd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        rd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        rd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        rd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        rd.EventType = GetEventProperty(pEvent, pInfo, L"EventType");
        rd.TargetObject = GetEventProperty(pEvent, pInfo, L"TargetObject");

        SysmonEvent temp_SE;
        temp_SE.eventId = eventId;
        temp_SE.timestamp_wstring = rd.UtcTime;
        temp_SE.timestamp = UtcTimeToLong(rd.UtcTime);
        temp_SE.eventData = rd;

        myTracker.LogProcessing(temp_SE);
        break;
    }

    case 13: { // Registry Event (Value Set)
        ID_13_SYSMONEVENT_REG_SETVALUE rd;

        rd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        rd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        rd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        rd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        rd.EventType = GetEventProperty(pEvent, pInfo, L"EventType");
        rd.TargetObject = GetEventProperty(pEvent, pInfo, L"TargetObject");
        rd.Details = GetEventProperty(pEvent, pInfo, L"Details");

        SysmonEvent temp_SE;
        temp_SE.eventId = eventId;
        temp_SE.timestamp_wstring = rd.UtcTime;
        temp_SE.timestamp = UtcTimeToLong(rd.UtcTime);
        temp_SE.eventData = rd;

        myTracker.LogProcessing(temp_SE);
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