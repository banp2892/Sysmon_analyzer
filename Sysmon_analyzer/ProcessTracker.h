/**
*@file ProcessTracker.h
* @todo нужно добавить еще параметров
* @todo скорее всего нужно будет использовать две нейронки, рекурсивную и дефолтную?? (почитать про это)
* 
*/

#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <set>
#include <iostream>
#include <variant>

#include "Structures.h"
#include "PathNormalizer.h"

struct ProcessNode {
    

    long long FirstEventTime; ///< [FirstEventTime] Время первого пришедшего лога
    long long LastEventTime; ///< [LastEventTime] Время последнего пришедшего лога

    std::wstring ParentProcessGuid;  ///< [ParentProcessGuid] GUID родительского процесса
    DWORD ParentProcessId;           ///< [ParentProcessId] PID родительского процесса
    std::wstring ParentImage;        ///< [ParentImage] Путь к исполняемому файлу родителя
    std::vector<std::wstring> ChildrenGuids; ///< [ChildrenGuids] Список ключей к потомкам

    std::vector<std::wstring> SequenceNamesForThisKey; ///< [SequenceNamesForThisKey] Последовательность Guid, от текущего ключа Key
    std::vector<UCHAR>SequenceID;///< [SequenceID] Последовательность ID выполняемых Key
};

class ProcessTracker {
public:

    /**
    * @brief Первичная обработка приходяшего лога
    * @param NewLog - структура специального вида, в которую записан весь лог!
    */
    void LogProcessing(const SysmonEvent& NewLog);

    void UpdateProcessNode(std::wstring& Name, SysmonEvent MyEvent);
    void AddNewProcessNode(std::wstring& currentGuid, SysmonEvent NewLog);

    void ShowProcessesMonitor();


        

private:
    std::map<std::wstring, ProcessNode> _processes; ///< wstring <-> key, в данном случае key это имя процесса
    std::mutex _dataMutex;


};

