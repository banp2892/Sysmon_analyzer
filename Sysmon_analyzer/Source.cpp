
/**
* @todo Нужно соеденить в один exe мой код и Sysmon, чтобы было проще использовать
* @todo проверит каждый из айдишников (написать првоеряющую прогу, которая по очереди вызовет необходимые функции)
*/


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