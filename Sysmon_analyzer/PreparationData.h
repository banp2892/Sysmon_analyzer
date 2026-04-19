#pragma once

// Windows.h ДОЛЖЕН быть выше остальных, чтобы типы типа DWORD были видны сразу
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h> 

#include <string>
#include <vector>
#include <cmath>
#include <map>
#include <algorithm>

struct EventFeature {
    long long timestamp;
    int eventId;
    std::wstring imagePath;
    std::wstring cmdLine;
    std::wstring destIp;
    DWORD destPort; // Теперь DWORD точно будет определен
    double entropy;

    static double CalculateEntropy(const std::wstring& s) {
        if (s.empty()) return 0.0;

        std::map<wchar_t, int> counts;
        for (size_t i = 0; i < s.size(); ++i) {
            counts[s[i]]++;
        }

        double ent = 0.0;
        // Используем итератор вместо [ch, count], чтобы не требовать C++17
        for (std::map<wchar_t, int>::const_iterator it = counts.begin(); it != counts.end(); ++it) {
            double p = (double)it->second / s.size();
            ent -= p * (log(p) / log(2.0)); // log2 может не быть в старых VS, это замена
        }
        return ent;
    }

    std::wstring ToCSV() const {
        // Убедись, что используешь to_wstring, так как мы возвращаем wstring
        return std::to_wstring(eventId) + L"," +
            imagePath + L"," +
            std::to_wstring(destPort) + L"," +
            std::to_wstring(entropy);
    }
};