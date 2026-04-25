#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <set>
#include <iostream>
#include <variant>

#include "Structures.h"
#include "PathNormalizer.h"

struct ProcessNode {

    long long FirstEventTime;
    long long LastEventTime;
    std::vector<UCHAR>Sequence;
};

class ProcessTracker {
public:

    /**
    * @brief Первичная обработка приходяшего лога
    * @param NewLog - структура специального вида, в которую записан весь лог!
    */
    void LogProcessing(const SysmonEvent& NewLog);

    void UpdateProcessNode(std::wstring& Name, SysmonEvent MyEvent);
    void AddNewProcessNode(std::wstring& currentGuid, SysmonEvent NewLog);

    void ShowProcessesMonitor();


        

private:
    std::map<std::wstring, ProcessNode> _processes;
    std::mutex _dataMutex;
    PathNormalizer _normalizer;
};

