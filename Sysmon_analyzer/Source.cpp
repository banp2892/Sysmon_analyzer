
#include <iostream>
#include <vector>
#include <clocale>


#pragma comment(lib, "tdh.lib")

#include "SysmonCollector.h"
#include "PreparationData.h"

int main() {
    setlocale(LC_ALL, "Russian");
    PreparationData preparator;

    SysmonCollector collector(L"MySysmonSession", &preparator);

    collector.Run();
    return 0;
}