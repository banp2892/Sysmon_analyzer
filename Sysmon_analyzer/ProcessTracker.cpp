#include "ProcessTracker.h"
#include <iostream>

void ProcessTracker::LogProcessing(const SysmonEvent& NewLog)
{
    // Исправленный синтаксис лямбды и constexpr
    std::wstring currentGuid = std::visit([](auto&& arg) -> std::wstring {
        if constexpr (requires { arg.ProcessGuid; }) {
            return arg.ProcessGuid;
        }
        return L"";
        }, NewLog.eventData);

    if (currentGuid.empty()) {
        std::wcout << L"Skipping event ID: " << NewLog.eventId << std::endl;
        return;
    }

    std::wcout << L"Processing GUID: " << currentGuid <<L" ID = "<< NewLog.eventId << std::endl;
}
