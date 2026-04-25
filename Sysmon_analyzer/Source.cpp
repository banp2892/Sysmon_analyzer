
/**
* @todo Нужно соеденить в один exe мой код и Sysmon, чтобы было проще использовать
* @todo проверит каждый из айдишников (написать првоеряющую прогу, которая по очереди вызовет необходимые функции)
*/


#include <iostream>
#include <vector>
#include <clocale>


#pragma comment(lib, "tdh.lib")

#include "SysmonCollector.h"


int main() {
    std::wcout.imbue(std::locale("rus_rus.1251"));
    setlocale(LC_ALL, "Russian");




    SysmonCollector collector(L"MySysmonSession");

    collector.Run();
    return 0;
}