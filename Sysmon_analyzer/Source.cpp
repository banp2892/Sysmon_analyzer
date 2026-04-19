
#include <iostream>
#include <vector>

#include <windows.h> // ULONG, WCHAR

#include <evntrace.h> // Основные функции и структуры трассировки
#include <evntcons.h> // Константы для потребителей событий

#include <iomanip> // для чтения числа DWORD


#include <tdh.h>
#pragma comment(lib, "tdh.lib")

/**
* @brief Настраивает буфер для сессии трассировки
* @note Запускаем чтобы создать структуру EVENT_TRACE_PROPERTIES, которую в дальнейшем будем использовать
*/

void SetupTraceProperties(std::vector<unsigned char>& buffer, const wchar_t* sessionName) {
	ULONG buffer_size = sizeof(EVENT_TRACE_PROPERTIES) + (2 * MAX_PATH * sizeof(WCHAR));

	buffer.assign(buffer_size, 0);
	
	EVENT_TRACE_PROPERTIES* properies = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());

	properies->Wnode.BufferSize = buffer_size; // устанавливаем размер буффера
	properies->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	properies->Wnode.Guid = { 0 };

	properies->LogFileMode = EVENT_TRACE_REAL_TIME_MODE; // Режим реального времени

	properies->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

	wchar_t* nameLocation = reinterpret_cast<wchar_t*>(buffer.data() + properies->LoggerNameOffset);
	wcscpy_s(nameLocation, MAX_PATH, sessionName);

}



/** @brief Вспомогательная функция для получения ЧИСЛА(DWORD)
*/ 
DWORD GetEventPropertyInt(PEVENT_RECORD pEvent, const wchar_t* propertyName) {
	PROPERTY_DATA_DESCRIPTOR descriptor;
	descriptor.PropertyName = (ULONGLONG)propertyName;
	descriptor.ArrayIndex = 0;

	DWORD propertyValue = 0;
	DWORD bufferSize = sizeof(DWORD);

	if (TdhGetProperty(pEvent, 0, NULL, 1, &descriptor, bufferSize, (PBYTE)&propertyValue) == ERROR_SUCCESS) {
		return propertyValue;
	}
	return 0;
}

/** @brief Вспомогательная функция для получения значения свойства как строки
*/ 
std::wstring GetEventProperty(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, const wchar_t* propertyName) {
	PROPERTY_DATA_DESCRIPTOR descriptor;
	descriptor.PropertyName = (ULONGLONG)propertyName;
	descriptor.ArrayIndex = 0;

	DWORD bufferSize = 0;
	TdhGetPropertySize(pEvent, 0, NULL, 1, &descriptor, &bufferSize);

	std::vector<BYTE> propertyBuffer(bufferSize);
	// 2. Получаем сами данные
	if (TdhGetProperty(pEvent, 0, NULL, 1, &descriptor, bufferSize, propertyBuffer.data()) == ERROR_SUCCESS) {
		return std::wstring((wchar_t*)propertyBuffer.data());
	}
	return L"";
}

void WINAPI OnEventRecord(PEVENT_RECORD pEvent) {
	DWORD bufferSize = 0;
	PTRACE_EVENT_INFO pInfo = NULL;

	if (TdhGetEventInformation(pEvent, 0, NULL, pInfo, &bufferSize) == ERROR_INSUFFICIENT_BUFFER) {
		pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize); // сначала задаем размер буфера
		if (TdhGetEventInformation(pEvent, 0, NULL, pInfo, &bufferSize) == ERROR_SUCCESS) {



			// Если это ID 3 (Network Connection)
			if (pEvent->EventHeader.EventDescriptor.Id == 3) {
				std::wstring UtcTime = GetEventProperty(pEvent, pInfo, L"UtcTime");
				std::wstring imagePath = GetEventProperty(pEvent, pInfo, L"Image");
				std::wstring destIp = GetEventProperty(pEvent, pInfo, L"DestinationIp");
				 
				DWORD destPort = GetEventPropertyInt(pEvent, L"DestinationPort");

				std::wcout << L"[NET] TIME: " << UtcTime<< L" " << imagePath
					<< L" -> " << destIp << L":" << destPort << std::endl;
			}

			// Если это ID 1 (Process Create)
			if (pEvent->EventHeader.EventDescriptor.Id == 1) {
				std::wstring commandLine = GetEventProperty(pEvent, pInfo, L"CommandLine");
				std::wcout << L"[PROC] New process: " << commandLine << std::endl;
			}

			
		}
		free(pInfo);
	}
}




int main(int argc, char* argv[]) {
	
	setlocale(LC_ALL, "Russian");

	const wchar_t* sessionName = L"MySysmode";
	std::vector<unsigned char> buffer;
	SetupTraceProperties(buffer, sessionName);

	EVENT_TRACE_PROPERTIES* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());

	TRACEHANDLE sessionHandle = 0;
	//CONTROLTRACE_ID sessionCT_ID_exit = 0;

	ULONG status_exit = ControlTrace(NULL, sessionName, properties, EVENT_TRACE_CONTROL_STOP); // закрываем открытую раннее сессию!

	ULONG status = StartTraceW(&sessionHandle, sessionName, properties);

	if (status == ERROR_SUCCESS) {
		std::cout << "Сессия успешно запущена!" << std::endl;
	}
	else {
		std::cerr << "Ошибка запуска: " << status << std::endl;
	}

	// GUID Sysmon: {5770385f-c22a-43e0-bf4c-06f5698ffbd9} 
	/** @todo Этот Guid скорее всего уникальный? нужно как-то научиться его определять
	*/
	static const GUID SysmonGuid =
	{ 0x5770385f, 0xc22a, 0x43e0, { 0xbf, 0x4c, 0x06, 0xf5, 0x69, 0x8f, 0xfb, 0xd9 } }; 

	ULONG enable_status = EnableTraceEx2(sessionHandle, &SysmonGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
	if (enable_status == ERROR_SUCCESS) {
		std::cout << "Sysmon подключен к сессии!" << std::endl;
	}
	else {
		std::cerr << "Ошибка подключения Sysmon: " << enable_status << std::endl;
	}

	EVENT_TRACE_LOGFILEW logFile = {0};
	logFile.LoggerName = (LPWSTR)sessionName;
	logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;

	logFile.EventRecordCallback = [](PEVENT_RECORD pEvent) {
		OnEventRecord(pEvent);
		};
	TRACEHANDLE traceHandle = OpenTraceW(&logFile);

	if (traceHandle == INVALID_PROCESSTRACE_HANDLE) {
		std::cerr << "Произошла ошибка при OpenTraceW: " << GetLastError() << std::endl;
		return 1;
	}

	std::cout << "Начинаю обработку событий... (нажмите Ctrl+C для выхода)" << std::endl;

	// ВНИМАНИЕ: Эта функция заблокирует поток здесь и будет ждать событий
	ULONG processStatus = ProcessTrace(&traceHandle, 1, NULL, NULL);

	if (processStatus != ERROR_SUCCESS) {
		std::cerr << "ProcessTrace завершился с ошибкой: " << processStatus << std::endl;
	}

}