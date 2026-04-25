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
    //std::wcout << L"DEBUG: Received ID " << eventId << std::endl;

    SysmonEvent temp_SE;
    temp_SE.eventId = eventId;

    switch (eventId) {
    case 1: { ///< Событие создания процесса (Process Create)
        ID_1_SYSMONEVENT_CREATE_PROCESS pd;


        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.LogonGuid = GetGuidProperty(pEvent, L"LogonGuid");
        pd.LogonId = GetEventProperty(pEvent, pInfo, L"LogonId");
        pd.TerminalSessionId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"TerminalSessionId"));
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.CommandLine = GetEventProperty(pEvent, pInfo, L"CommandLine");
        pd.CurrentDirectory = GetEventProperty(pEvent, pInfo, L"CurrentDirectory");
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.IntegrityLevel = GetEventProperty(pEvent, pInfo, L"IntegrityLevel");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.FileVersion = GetEventProperty(pEvent, pInfo, L"FileVersion");
        pd.Description = GetEventProperty(pEvent, pInfo, L"Description");
        pd.Product = GetEventProperty(pEvent, pInfo, L"Product");
        pd.Company = GetEventProperty(pEvent, pInfo, L"Company");
        pd.OriginalFileName = GetEventProperty(pEvent, pInfo, L"OriginalFileName");
        pd.Hashes = GetEventProperty(pEvent, pInfo, L"Hashes");
        pd.ParentProcessGuid = GetGuidProperty(pEvent, L"ParentProcessGuid");
        pd.ParentProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ParentProcessId"));
        pd.ParentImage = GetEventProperty(pEvent, pInfo, L"ParentImage");
        pd.ParentCommandLine = GetEventProperty(pEvent, pInfo, L"ParentCommandLine");
        pd.ParentUser = GetEventProperty(pEvent, pInfo, L"ParentUser");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;

        break;
    }

    case 2: { ///< Изменение времени создания файла (File Creation Time Changed)
        ID_2_SYSMONEVENT_FILE_TIME pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.TargetFilename = GetEventProperty(pEvent, pInfo, L"TargetFilename");
        pd.CreationUtcTime = GetEventProperty(pEvent, pInfo, L"CreationUtcTime");
        pd.PreviousCreationUtcTime = GetEventProperty(pEvent, pInfo, L"PreviousCreationUtcTime");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;

        break;
    }

    case 3: { ///< Сетевое соединение (Network Connection)
        ID_3_SYSMONEVENT_NETWORK_CONNECT pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.Protocol = GetEventProperty(pEvent, pInfo, L"Protocol");
        pd.Initiated = GetEventProperty(pEvent, pInfo, L"Initiated");
        pd.SourceIsIpv6 = GetEventProperty(pEvent, pInfo, L"SourceIsIpv6");
        pd.SourceIp = GetEventProperty(pEvent, pInfo, L"SourceIp");
        pd.SourceHostname = GetEventProperty(pEvent, pInfo, L"SourceHostname");
        pd.SourcePort = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"SourcePort"));
        pd.SourcePortName = GetEventProperty(pEvent, pInfo, L"SourcePortName");
        pd.DestinationIsIpv6 = GetEventProperty(pEvent, pInfo, L"DestinationIsIpv6");
        pd.DestinationIp = GetEventProperty(pEvent, pInfo, L"DestinationIp");
        pd.DestinationHostname = GetEventProperty(pEvent, pInfo, L"DestinationHostname");
        pd.DestinationPort = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"DestinationPort"));
        pd.DestinationPortName = GetEventProperty(pEvent, pInfo, L"DestinationPortName");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;

        break;
    }

    case 4: { ///< Изменение состояния службы Sysmon (Service State Change)
        ID_4_SYSMONEVENT_SERVICE_STATE_CHANGE pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.Version = GetEventProperty(pEvent, pInfo, L"Version");
        pd.SchemaVersion = GetEventProperty(pEvent, pInfo, L"SchemaVersion");
        pd.State = GetEventProperty(pEvent, pInfo, L"State");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;

        break;
    }

    case 5: { ///< Процесс завершен (Process Terminated)
        ID_5_SYSMONEVENT_PROCESS_TERMINATE pd;


        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;

        break;
    }

    case 6: { ///< Загрузка драйвера в систему (Driver Loaded)
        ID_6_SYSMONEVENT_DRIVER_LOAD pd;


        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.ImageLoaded = GetEventProperty(pEvent, pInfo, L"ImageLoaded");
        pd.Hashes = GetEventProperty(pEvent, pInfo, L"Hashes");
        pd.Signed = GetEventProperty(pEvent, pInfo, L"Signed");
        pd.Signature = GetEventProperty(pEvent, pInfo, L"Signature");
        pd.SignatureStatus = GetEventProperty(pEvent, pInfo, L"SignatureStatus");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;

        break;
    }
    case 7: { ///< Загрузка модуля в процесс (Image Loaded)
        ID_7_SYSMONEVENT_IMAGE_LOAD pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.ImageLoaded = GetEventProperty(pEvent, pInfo, L"ImageLoaded");
        pd.FileVersion = GetEventProperty(pEvent, pInfo, L"FileVersion");
        pd.Description = GetEventProperty(pEvent, pInfo, L"Description");
        pd.Product = GetEventProperty(pEvent, pInfo, L"Product");
        pd.Company = GetEventProperty(pEvent, pInfo, L"Company");
        pd.OriginalFileName = GetEventProperty(pEvent, pInfo, L"OriginalFileName");
        pd.Hashes = GetEventProperty(pEvent, pInfo, L"Hashes");
        pd.Signed = GetEventProperty(pEvent, pInfo, L"Signed");
        pd.Signature = GetEventProperty(pEvent, pInfo, L"Signature");
        pd.SignatureStatus = GetEventProperty(pEvent, pInfo, L"SignatureStatus");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;

        break;
    }

    case 8: { ///< Создание удаленного потока в другом процессе (CreateRemoteThread)
        ID_8_SYSMONEVENT_CREATE_REMOTE_THREAD pd;


        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.SourceProcessGuid = GetGuidProperty(pEvent, L"SourceProcessGuid");
        pd.SourceProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"SourceProcessId"));
        pd.SourceImage = GetEventProperty(pEvent, pInfo, L"SourceImage");
        pd.SourceUser = GetEventProperty(pEvent, pInfo, L"SourceUser");
        pd.TargetProcessGuid = GetGuidProperty(pEvent, L"TargetProcessGuid");
        pd.TargetProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"TargetProcessId"));
        pd.TargetImage = GetEventProperty(pEvent, pInfo, L"TargetImage");
        pd.TargetUser = GetEventProperty(pEvent, pInfo, L"TargetUser");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.NewThreadId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"NewThreadId"));
        pd.StartAddress = GetEventProperty(pEvent, pInfo, L"StartAddress");
        pd.StartModule = GetEventProperty(pEvent, pInfo, L"StartModule");
        pd.StartFunction = GetEventProperty(pEvent, pInfo, L"StartFunction");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;

        break;
    }

    case 9: { ///< Прямое чтение диска (Raw Access Read)
        ID_9_SYSMONEVENT_RAWACCESS_READ pd;


        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.Device = GetEventProperty(pEvent, pInfo, L"Device");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;

        break;
    }

    

    case 10: { ///< Доступ к процессу (Process Access)
        ID_10_SYSMONEVENT_ACCESS_PROCESS pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.SourceProcessGUID = GetGuidProperty(pEvent, L"SourceProcessGuid");
        pd.SourceProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"SourceProcessId"));
        pd.SourceThreadId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"SourceThreadId"));
        pd.SourceImage = GetEventProperty(pEvent, pInfo, L"SourceImage");
        pd.SourceUser = GetEventProperty(pEvent, pInfo, L"SourceUser");
        pd.TargetProcessGUID = GetGuidProperty(pEvent, L"TargetProcessGuid");
        pd.TargetProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"TargetProcessId"));
        pd.TargetImage = GetEventProperty(pEvent, pInfo, L"TargetImage");
        pd.TargetUser = GetEventProperty(pEvent, pInfo, L"TargetUser");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.GrantedAccess = GetEventProperty(pEvent, pInfo, L"GrantedAccess");
        pd.CallTrace = GetEventProperty(pEvent, pInfo, L"CallTrace");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;

        break;
    }

    case 11: { ///< Создание файла (File Create)
        ID_11_SYSMONEVENT_FILE_CREATE pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.TargetFilename = GetEventProperty(pEvent, pInfo, L"TargetFilename");
        pd.CreationUtcTime = GetEventProperty(pEvent, pInfo, L"CreationUtcTime");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;

        break;
    }

    case 12: { ///< Создание или удаление объекта реестра (Registry Object Create/Delete)
        ID_12_SYSMONEVENT_REG_KEY pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.EventType = GetEventProperty(pEvent, pInfo, L"EventType");
        pd.TargetObject = GetEventProperty(pEvent, pInfo, L"TargetObject");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;

        break;
    }

    case 13: { ///< Изменение или создание значения в реестре (Registry Value Set)
        ID_13_SYSMONEVENT_REG_SETVALUE pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.EventType = GetEventProperty(pEvent, pInfo, L"EventType");
        pd.TargetObject = GetEventProperty(pEvent, pInfo, L"TargetObject");
        pd.Details = GetEventProperty(pEvent, pInfo, L"Details");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;

        break;
    }
    case 14: { ///< Переименование объекта реестра (Registry Object Rename)
        ID_14_SYSMONEVENT_REG_NAME pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.EventType = GetEventProperty(pEvent, pInfo, L"EventType");
        pd.TargetObject = GetEventProperty(pEvent, pInfo, L"TargetObject");
        pd.NewName = GetEventProperty(pEvent, pInfo, L"NewName");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;

        break;
    }
    case 15: { ///< Создание альтернативного потока данных (File Create Stream Hash)
        ID_15_SYSMONEVENT_FILE_CREATE_STREAM_HASH pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.TargetFilename = GetEventProperty(pEvent, pInfo, L"TargetFilename");
        pd.CreationUtcTime = GetEventProperty(pEvent, pInfo, L"CreationUtcTime");
        pd.Hash = GetEventProperty(pEvent, pInfo, L"Hash");
        pd.Contents = GetEventProperty(pEvent, pInfo, L"Contents");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;

        break;
    }

    case 16: { ///< Изменение конфигурации Sysmon (Service Configuration Change)
        ID_16_SYSMONEVENT_SERVICE_CONFIGURATION_CHANGE pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.Configuration = GetEventProperty(pEvent, pInfo, L"Configuration");
        pd.ConfigurationFileHash = GetEventProperty(pEvent, pInfo, L"ConfigurationFileHash");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;

        break;
    }

    case 17: { ///< Создание именованного канала (Pipe Created)
        ID_17_SYSMONEVENT_CREATE_NAMEDPIPE pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.EventType = GetEventProperty(pEvent, pInfo, L"EventType");
        pd.PipeName = GetEventProperty(pEvent, pInfo, L"PipeName");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;

        break;
    }
    case 18: { ///< Подключение к именованному каналу (Pipe Connected)
        ID_18_SYSMONEVENT_CONNECT_NAMEDPIPE pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.EventType = GetEventProperty(pEvent, pInfo, L"EventType");
        pd.PipeName = GetEventProperty(pEvent, pInfo, L"PipeName");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;
        break;
    }


    case 19: { ///< Регистрация фильтра событий WMI (WmiEventFilter activity detected)
        ID_19_SYSMONEVENT_WMI_FILTER pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.Operation = GetEventProperty(pEvent, pInfo, L"Operation");
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.EventType = GetEventProperty(pEvent, pInfo, L"EventType");
        pd.EventNamespace = GetEventProperty(pEvent, pInfo, L"EventNamespace");
        pd.Name = GetEventProperty(pEvent, pInfo, L"Name");
        pd.Query = GetEventProperty(pEvent, pInfo, L"Query");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;
        break;
    }
    case 20: { ///< Регистрация потребителя событий WMI (WmiEventConsumer activity detected)
        ID_20_SYSMONEVENT_WMI_CONSUMER pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.Operation = GetEventProperty(pEvent, pInfo, L"Operation");
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.EventType = GetEventProperty(pEvent, pInfo, L"EventType");
        pd.Name = GetEventProperty(pEvent, pInfo, L"Name");
        pd.Type = GetEventProperty(pEvent, pInfo, L"Type");
        pd.Destination = GetEventProperty(pEvent, pInfo, L"Destination");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;
        break;
    }
    case 21: { ///< Связывание фильтра и потребителя WMI (WmiEventConsumerToFilter activity detected)
        ID_21_SYSMONEVENT_WMI_BINDING pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.Operation = GetEventProperty(pEvent, pInfo, L"Operation");
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.EventType = GetEventProperty(pEvent, pInfo, L"EventType");
        pd.Consumer = GetEventProperty(pEvent, pInfo, L"Consumer");
        pd.Filter = GetEventProperty(pEvent, pInfo, L"Filter");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;
        break;
    }
    case 22: { ///< DNS-запрос (DNS Query)
        ID_22_SYSMONEVENT_DNS_QUERY pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.QueryName = GetEventProperty(pEvent, pInfo, L"QueryName");
        pd.QueryStatus = GetEventProperty(pEvent, pInfo, L"QueryStatus");
        pd.QueryResults = GetEventProperty(pEvent, pInfo, L"QueryResults");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;
        break;
    }
    case 23: { ///< Удаление файла с архивацией (File Delete archived)
        ID_23_SYSMONEVENT_FILE_DELETE pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.TargetFilename = GetEventProperty(pEvent, pInfo, L"TargetFilename");
        pd.Hashes = GetEventProperty(pEvent, pInfo, L"Hashes");
        pd.IsExecutable = GetEventProperty(pEvent, pInfo, L"IsExecutable");
        pd.Archived = GetEventProperty(pEvent, pInfo, L"Archived");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;
        break;
    }

    case 24: { ///< Изменение содержимого буфера обмена (Clipboard change)
        ID_24_SYSMONEVENT_CLIPBOARD pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.Session = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"Session"));
        pd.ClientInfo = GetEventProperty(pEvent, pInfo, L"ClientInfo");
        pd.Hashes = GetEventProperty(pEvent, pInfo, L"Hashes");
        pd.Archived = GetEventProperty(pEvent, pInfo, L"Archived");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;
        break;
    }

    case 25: { ///< Подмена образа процесса (Process Tampering)
        ID_25_SYSMONEVENT_PROCESS_IMAGE_TAMPERING pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.Type = GetEventProperty(pEvent, pInfo, L"Type");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;
        break;
    }
    case 26: { ///< Удаление файла без архивации (File Delete detected)
        ID_26_SYSMONEVENT_FILE_DELETE_DETECTED pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.TargetFilename = GetEventProperty(pEvent, pInfo, L"TargetFilename");
        pd.Hashes = GetEventProperty(pEvent, pInfo, L"Hashes");
        pd.IsExecutable = GetEventProperty(pEvent, pInfo, L"IsExecutable");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;
        break;
    }

    case 27: { ///< Блокировка создания исполняемого файла (File Block Executable)
        ID_27_SYSMONEVENT_FILE_BLOCK_EXE pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.TargetFilename = GetEventProperty(pEvent, pInfo, L"TargetFilename");
        pd.Hashes = GetEventProperty(pEvent, pInfo, L"Hashes");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;
        break;
    }

    case 28: { ///< Блокировка уничтожения файла (File Block Shredding)
        ID_28_SYSMONEVENT_FILE_BLOCK_SHREDDING pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.TargetFilename = GetEventProperty(pEvent, pInfo, L"TargetFilename");
        pd.Hashes = GetEventProperty(pEvent, pInfo, L"Hashes");
        pd.IsExecutable = GetEventProperty(pEvent, pInfo, L"IsExecutable");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;
        break;
    }
    case 29: { ///< Обнаружение записи исполняемого файла (File Executable Detected)
        ID_29_SYSMONEVENT_FILE_EXE_DETECTED pd;

        pd.UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
        pd.ProcessGuid = GetGuidProperty(pEvent, L"ProcessGuid");
        pd.ProcessId = static_cast<DWORD>(GetEventPropertyInt(pEvent, L"ProcessId"));
        pd.User = GetEventProperty(pEvent, pInfo, L"User");
        pd.Image = GetEventProperty(pEvent, pInfo, L"Image");
        pd.RuleName = GetEventProperty(pEvent, pInfo, L"RuleName");
        pd.TargetFilename = GetEventProperty(pEvent, pInfo, L"TargetFilename");
        pd.Hashes = GetEventProperty(pEvent, pInfo, L"Hashes");

        temp_SE.eventData = pd;
        temp_SE.timestamp_wstring = pd.UtcTime;
        break;
    }


    default:
        std::wcout << L"[" << GetEventProperty(pEvent, pInfo, L"UtcTime") << L"] [ID:" << eventId << L"] Generic Event detected." << std::endl;
        break;
    }

    /** * @brief Упаковка данных в универсальный контейнер SysmonEvent.
    */
    if (!temp_SE.timestamp_wstring.empty()) {
        temp_SE.timestamp = UtcTimeToLong(temp_SE.timestamp_wstring);
        myTracker.LogProcessing(temp_SE);
    }


    if (!temp_SE.timestamp_wstring.empty()) {
        temp_SE.timestamp = UtcTimeToLong(temp_SE.timestamp_wstring);
        myTracker.LogProcessing(temp_SE);
        static int eventCounter = 0;
        eventCounter++;

        if (eventCounter >= 50) {
            myTracker.ShowProcessesMonitor();
            eventCounter = 0;
        }
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

    //std::wcout << L"!" << std::flush;
    DWORD size = 0;
    if (TdhGetEventInformation(pEvent, 0, NULL, NULL, &size) == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<BYTE> info(size);
        auto pInfo = (PTRACE_EVENT_INFO)info.data();
        if (TdhGetEventInformation(pEvent, 0, NULL, pInfo, &size) == ERROR_SUCCESS) {
            ParseAndLog(pEvent, pInfo);
        }
    }
}