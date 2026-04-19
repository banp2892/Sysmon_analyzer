#include <windows.h> // ULONG, WCHAR

#include <evntrace.h> // Основные функции и структуры трассировки
#include <evntcons.h> // Константы для потребителей событий

#include <iomanip> // для чтения числа DWORD


#include <tdh.h>
#pragma comment(lib, "tdh.lib")


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

				std::wcout << L"[NET] TIME: " << UtcTime << L" " << imagePath
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
