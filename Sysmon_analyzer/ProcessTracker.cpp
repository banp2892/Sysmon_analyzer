#include "ProcessTracker.h"
#include <iomanip>
#include <sstream>

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

    std::lock_guard<std::mutex> lock(_dataMutex);



    if (NewLog.eventId == 1) {
        const auto& data = std::get<ID_1_SYSMONEVENT_CREATE_PROCESS>(NewLog.eventData);

        std::wstring normImage = _normalizer.Normalize(data.Image);
        std::wstring normCmd = _normalizer.Normalize(data.CommandLine);

    }
    

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

void ProcessTracker::UpdateProcessNode(std::wstring& currentGuid, SysmonEvent NewLog)
{
    _processes[currentGuid].Sequence.push_back(NewLog.eventId); ///> Добавили в конец последовательности ID пришедшего лога
    _processes[currentGuid].LastEventTime = NewLog.timestamp; ///> меняем время последнего лога для текущего процесса

}

void ProcessTracker::AddNewProcessNode(std::wstring& currentGuid, SysmonEvent NewLog)
{
    _processes[currentGuid].Sequence.push_back(NewLog.eventId); ///> Добавили в конец последовательности ID пришедшего лога
    _processes[currentGuid].LastEventTime = NewLog.timestamp; ///> Устанавливаем время, когда открыли запись для текущего процесса
    _processes[currentGuid].FirstEventTime = NewLog.timestamp;///> меняем время последнего лога для текущего процесса


}


void ProcessTracker::ShowProcessesMonitor() {
    // В ОДНОМ ПОТОКЕ МЬЮТЕКС НЕ НУЖЕН. Если оставил поток - закомментируй эту строку:
    // std::lock_guard<std::mutex> lock(_dataMutex); 

    if (_processes.empty()) {
        //system("cls");
        std::wcout << L"Waiting for Sysmon events (Try to open Notepad...)" << std::endl;
        return;
    }

    //system("cls");
    std::wcout << L"==================== IDS PROCESS MONITOR ====================" << std::endl;
    std::wcout << L" Total processes tracked: " << _processes.size() << std::endl;
    std::wcout << L"------------------------------------------------------------" << std::endl;
    std::wstringstream ss;
    for (const auto& [guid, node] : _processes) {
        ss<<"GUID: "<< guid << std::endl;
        ss << "First Time: " << node.FirstEventTime << std::endl;
        ss << "Last Time: " << node.LastEventTime << std::endl;

        ss << "Seq: ";
        for (auto ID_number : node.Sequence) {
            ss << ID_number << ", ";
        }
        ss << std::endl;
        ss<<"-----------------------"<< std::endl;

    }








    std::wstring OutputData = ss.str();
    std::wcout << OutputData;
    // ПРИНУДИТЕЛЬНО выталкиваем данные в консоль
    std::wcout << std::flush;
}