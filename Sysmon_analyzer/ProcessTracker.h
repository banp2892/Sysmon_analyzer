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

struct ProcessNode {
    std::wstring Guid;
    DWORD PID;
    std::wstring ParentGuid;
    std::wstring StartTime;
    std::wstring LastEventTime;
    std::vector<USHORT> Sequence;
    int EventCount = 0;
};

class ProcessTracker {
public:
    void LogProcessing(const SysmonEvent& NewLog) {
        auto getGuid = [](auto&& arg) -> std::wstring {
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

        //std::lock_guard<std::mutex> lock(_mutex);

        std::wcout << L"[TRACKER] ID: " << NewLog.eventId
            << L" | Time: " << NewLog.timestamp_wstring
            << L" | GUID: " << currentGuid << std::endl;
    }

private:
    std::map<std::wstring, ProcessNode> _processes;
    std::mutex _mutex;
};