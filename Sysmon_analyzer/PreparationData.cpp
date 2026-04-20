#include "PreparationData.h"

void PreparationData::PrepareProcess(ID_1_SYSMONEVENT_CREATE_PROCESS& data) {
    // Главная задача "мозга" — посчитать энтропию перед сохранением
    data.entropy = CalculateEntropy(data.CommandLine);

    // Здесь же можно добавить другие метрики, например, длину командной строки
}

void PreparationData::PrepareNetwork(ID_3_SYSMONEVENT_NETWORK_CONNECT& data) {
    // Для сетевых событий пока просто пропускаем, 
    // но здесь можно добавить проверку IP по черным спискам
}

double PreparationData::CalculateEntropy(const std::wstring& s) {
    if (s.empty()) return 0.0;

    std::map<wchar_t, int> counts;
    for (wchar_t c : s) counts[c]++;

    double entropy = 0.0;
    for (auto const& [ch, count] : counts) {
        double p = (double)count / s.size();
        entropy -= p * log2(p);
    }
    return entropy;
}