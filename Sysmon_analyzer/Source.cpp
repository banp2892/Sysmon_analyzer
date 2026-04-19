
#include <iostream>
#include <vector>


#include "SysmonCollector.h"
#pragma comment(lib, "tdh.lib")

int main() {
    setlocale(LC_ALL, "Russian");
    try {
        SysmonCollector collector(L"MySysmode");
        std::cout << "Система захвата запущена..." << std::endl;
        collector.Run(); // Здесь программа "зависнет" в ожидании событий
    }
    catch (...) {
        std::cerr << "Что-то пошло не так!" << std::endl;
    }
    return 0;
}