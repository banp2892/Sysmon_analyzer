
#include <iostream>
#include <vector>



#pragma comment(lib, "tdh.lib")

#include "SysmonCollector.h"
#include "PreparationData.h"

int main() {
    PreparationData preparator;

    // Передаем адрес объекта (&preparator), так как конструктор ждет PreparationData*
    SysmonCollector collector(L"MySysmonSession", &preparator);

    collector.Run();
    return 0;
}