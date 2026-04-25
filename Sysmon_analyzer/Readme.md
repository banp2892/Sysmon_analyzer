# Windows IDS (Intrusion Detection System) base on Sysmon & ETW

Учебный проект системы обнаружения вторжений, работающий через механизм трассировки событий Windows (ETW) и использующий Microsoft Sysmon в качестве поставщика данных.


### 1. Подготовка окружения
Для работы проекта необходим установленный Sysmon. 
1. Скачайте **Sysmon** с официального сайта [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
2. Распакуйте архив.
3. В папке с Sysmon переименуйте файл `Sysmon64.exe` в `SysmonTest.exe` (это необходимо для обхода конфликтов с уже имеющимися версиями или зависшими службами).

### 2. Установка драйвера
Запустите PowerShell от имени **Администратора** в папке с программой и выполните:
```powershell
./SysmonTest.exe -i -n -accepteula