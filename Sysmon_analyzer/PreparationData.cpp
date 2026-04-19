#include "PreparationData.h"

void PreparationData::PrepareProcess(ProcessData& data) {
    // Главная задача "мозга" — посчитать энтропию перед сохранением
    data.entropy = CalculateEntropy(data.commandLine);

    // Здесь же можно добавить другие метрики, например, длину командной строки
}

void PreparationData::PrepareNetwork(NetworkData& data) {
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