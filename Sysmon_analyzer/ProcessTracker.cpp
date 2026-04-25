#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#include "ProcessTracker.h"
#include <iomanip>
#include <sstream>

#include <fstream>
#include <codecvt>
#include <chrono>

auto now = std::chrono::system_clock::now();
auto duration = now.time_since_epoch();
auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();



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
        if (!_processes[currentGuid].SequenceNamesForThisGUID.empty()) {
            if (_processes[currentGuid].SequenceNamesForThisGUID.back() != Image) {
                _processes[currentGuid].SequenceNamesForThisGUID.push_back(Image); ///< добавляем имя файла, который что-то сделал 
            }
        }
        else {
            _processes[currentGuid].SequenceNamesForThisGUID.push_back(Image);
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
        if (!_processes[currentGuid].SequenceNamesForThisGUID.empty()) {
            if (_processes[currentGuid].SequenceNamesForThisGUID.back() != NormalizePathFunc(Pid1->Image)) {
                _processes[currentGuid].SequenceNamesForThisGUID.push_back(NormalizePathFunc(Pid1->Image)); ///< если пришел айди 1, и имя поменялось, то мы запишем имя
            }
        }
        else {
            _processes[currentGuid].SequenceNamesForThisGUID.push_back(Pid1->Image);
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

    system("cls");
    std::wstringstream ss;
    ss << "==================== IDS PROCESS MONITOR ====================" << std::endl;
    ss << " Total processes tracked: " << _processes.size() << std::endl;
    ss << "------------------------------------------------------------" << std::endl;
    

    for (const auto& [guid, node] : _processes) { ///< Для каждого процесса выводится такая табличка:
        ss<<"GUID: "<< guid << std::endl;
        ss << "First Time: " << node.FirstEventTime << std::endl;
        ss << "Last Time: " << node.LastEventTime << std::endl;

        ss << "Seq_ID: ";
        for (auto ID_number : node.SequenceID) {
            ss << ID_number << ", ";
        }
        ss << std::endl;


        ss << "Seq_Name: ";
        for (auto ID_number : node.SequenceNamesForThisGUID) {
            ss << ID_number << ", ";
        }
        ss << std::endl;









        ss<<"-----------------------"<< std::endl;
    }








    std::wstring OutputData = ss.str();


    

    std::wstring NameFile = L"Data_" + std::to_wstring(ms) + L".txt";
    std::wofstream outfile(NameFile, std::ios::out | std::ios::trunc);

    outfile.imbue(std::locale(std::locale::empty(), new std::codecvt_utf8<wchar_t>));

    if (outfile.is_open()) {
        outfile << OutputData;
        outfile.close();
    }


    std::wcout << OutputData;
    std::wcout << std::flush;
}