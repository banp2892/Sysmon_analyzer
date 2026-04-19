#pragma once


#include <windows.h> 

#include "Structures.h"
#include <cmath>
#include <map>

/**
 * @class PreparationData
 * @brief Класс для обработки сырых данных Sysmon и вычисления дополнительных признаков.
 */
class PreparationData {
public:
    /**
     * @brief Обрабатывает данные процесса (ID 1), вычисляя энтропию командной строки.
     * @param data Структура с первичными данными процесса.
     */
    void PrepareProcess(ProcessData& data);

    /**
     * @brief Подготавливает данные сетевого события (ID 3).
     * @param data Структура с сетевыми данными.
     */
    void PrepareNetwork(NetworkData& data);

    /**
     * @brief Универсальный метод расчета энтропии Шеннона для строки.
     * @param s Входная строка (командная строка, путь и т.д.)
     * @return Значение энтропии.
     */
    static double CalculateEntropy(const std::wstring& s);
};