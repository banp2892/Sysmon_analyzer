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


    

    if (_processes.contains(currentGuid)) { ///< нужно добавить вывод всего лога, если получили такую ситуацию
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
    _processes[currentGuid].SequenceID.push_back(NewLog.eventId); ///< Добавили в конец последовательности ID пришедшего лога
    _processes[currentGuid].LastEventTime = NewLog.timestamp; ///< меняем время последнего лога для текущего процесса

    auto getImage = [](auto&& arg)->std::wstring {
        if constexpr (requires { arg.Image; }) {
            return arg.Image;
        }
        return L"";
    };

    std::wstring Image = std::visit(getImage, NewLog.eventData);
    if (Image != L"") {
        if (_processes[currentGuid].NamesForThisGUID.back() != Image) {
            _processes[currentGuid].NamesForThisGUID.push_back(Image); ///< добавляем имя файла, который что-то сделал 
        }
    }

}

void ProcessTracker::AddNewProcessNode(std::wstring& currentGuid, SysmonEvent NewLog)
{
    _processes[currentGuid].SequenceID.push_back(NewLog.eventId); ///< Добавили в конец последовательности ID пришедшего лога
    _processes[currentGuid].LastEventTime = NewLog.timestamp; ///< Устанавливаем время, когда открыли запись для текущего процесса
    _processes[currentGuid].FirstEventTime = NewLog.timestamp;///< меняем время последнего лога для текущего процесса

    auto* Pid1 = std::get_if<ID_1_SYSMONEVENT_CREATE_PROCESS>(&NewLog.eventData); 
    if (Pid1) {
        if (!_processes[currentGuid].NamesForThisGUID.empty()) {
            if (_processes[currentGuid].NamesForThisGUID.back() != NormalizePathFunc(Pid1->Image)) {
                _processes[currentGuid].NamesForThisGUID.push_back(NormalizePathFunc(Pid1->Image)); ///< если пришел айди 1, и имя поменялось, то мы запишем имя
            }
        }
    }
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

    for (const auto& [guid, node] : _processes) { ///< Для каждого процесса выводится такая табличка:
        ss<<"GUID: "<< guid << std::endl;
        ss << "First Time: " << node.FirstEventTime << std::endl;
        ss << "Last Time: " << node.LastEventTime << std::endl;

        ss << "Seq_ID: ";
        for (auto ID_number : node.SequenceID) {
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