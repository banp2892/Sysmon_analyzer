#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <set>

#include "Structures.h"

struct ProcessNode {
    std::wstring Guid;
    DWORD PID;
    std::wstring ParentGuid;

    std::wstring StartTime;      // UtcTime из события ID 1
    std::wstring LastEventTime;  // UtcTime последнего пришедшего события

    std::vector<USHORT> Sequence; // Цепочка: 1->7->3...

    // Счетчики и флаги для метрик
    int EventCount = 0;
    bool AccessedLsass = false;
    std::set<std::wstring> UniqueDLLs;
    std::set<std::wstring> UniqueIPs;
    std::set<std::wstring> Extensions;


};

class ProcessTracker {
public:
    /**
    * @brief Первая принимает лог и дальше определяет, что с ним делать
    * @param SysmonEvent& NewLog - на входе полный лог считанный через Sysmon
    */
    void LogProcessing(const SysmonEvent& NewLog);


private:
    std::map<DWORD, ProcessNode> _processes; ///> DWORD - ключ, скорее всего Guid, ProcessNode - соответствующая процессу структура
    std::mutex _mutex; // Защита, так как ETW работает в несколько потоков
};