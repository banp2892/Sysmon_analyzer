#include "ProcessTracker.h"


void ProcessTracker::LogProcessing(const SysmonEvent& NewLog)
{
    auto getGuid = [](auto&& arg) -> std::wstring { ///< считываем GUID процесса - его уникальный номер!
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, std::monostate>) {
            return L"";
        }
        else if constexpr (requires { arg.ProcessGuid; }) {
            return arg.ProcessGuid;
        }
        else if constexpr (requires { arg.SourceProcessGUID; }) {
            return arg.SourceProcessGUID;
        }
        return L"";
        };

    std::wstring currentGuid = std::visit(getGuid, NewLog.eventData);
    if (currentGuid.empty()) return;

    std::lock_guard<std::mutex> lock(_mutex);


    std::wcout << L"[TRACKER] ID: " << NewLog.eventId
        << L" | GUID: " << currentGuid;
    if (NewLog.eventId == 3) {
        if (auto* netEvent = std::get_if<ID_3_SYSMONEVENT_NETWORK_CONNECT>(&NewLog.eventData)) {

            std::wcout << L"\n[!] NETWORK CONNECTION DETECTED" << std::endl;
            std::wcout << L"  Process:     " << netEvent->Image << L" (PID: " << netEvent->ProcessId << L")" << std::endl;
            std::wcout << L"  User:        " << netEvent->User << std::endl;
            std::wcout << L"  Rule:        " << (netEvent->RuleName.empty() ? L"None" : netEvent->RuleName) << std::endl;

            std::wcout << L"  Protocol:    " << netEvent->Protocol
                << L" (Initiated: " << netEvent->Initiated << L")" << std::endl;

            std::wcout << L"  Source:      " << netEvent->SourceIp << L":" << netEvent->SourcePort
                << L" (" << netEvent->SourceHostname << L")" << std::endl;

            std::wcout << L"  Destination: " << netEvent->DestinationIp << L":" << netEvent->DestinationPort;

            if (!netEvent->DestinationHostname.empty()) {
                std::wcout << L" [" << netEvent->DestinationHostname << L"]";
            }
            std::wcout << L" (" << netEvent->DestinationPortName << L")" << std::endl;

            std::wcout << L"  Time (UTC):  " << netEvent->UtcTime << std::endl;
            std::wcout << L"---------------------------------------------------" << std::endl;
        }
    }



    // 2. Специфический вывод нормализованных данных для ID 1
    if (NewLog.eventId == 1) {
        const auto& data = std::get<ID_1_SYSMONEVENT_CREATE_PROCESS>(NewLog.eventData);

        // Нормализуем Image и CommandLine
        std::wstring normImage = _normalizer.Normalize(data.Image);
        std::wstring normCmd = _normalizer.Normalize(data.CommandLine);

        std::wcout << L"\n  [NORM] Image: " << normImage
            << L"\n  [NORM] Cmd:   " << normCmd << std::endl;
    }
    else {
        std::wcout << std::endl;
    }

    // 3. Логика обновления мапы
    if (_processes.contains(currentGuid)) {
        if (NewLog.eventId == 1) {
            std::wcerr << L" [!] CRITICAL ANOMALY: ID 1 received for existing GUID: "
                << currentGuid << std::endl;
        }
        UpdateProcessNode(currentGuid, NewLog);
    }
    else {
        AddNewProcessNode(currentGuid, NewLog);
    }
    
    

}

void ProcessTracker::UpdateProcessNode(std::wstring& Name, SysmonEvent MyEvent)
{
    _processes[Name].Sequence.push_back(MyEvent.eventId); ///> Добавили в конец последовательности ID пришедшего лога
    _processes[Name].LastEventTime = MyEvent.timestamp; ///> меняем время последнего лога для текущего процесса

}

void ProcessTracker::AddNewProcessNode(std::wstring& currentGuid, SysmonEvent NewLog)
{
}
