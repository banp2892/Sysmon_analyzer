Write-Host "--- ЗАПУСК ТЕСТА IDS ---" -ForegroundColor Cyan

# 1 & 5: Процессы
$p = Start-Process calc.exe -PassThru
Start-Sleep -Seconds 1
Stop-Process $p.Id

# 11, 23, 26: Файлы
$testFile = "$env:TEMP\ids_test.txt"
"Test data" | Out-File $testFile
Remove-Item $testFile

# 22 & 3: DNS и Сеть
Resolve-DnsName "google.com" -ErrorAction SilentlyContinue
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.Connect("google.com", 80)
    $tcp.Close()
} catch {}

# 12, 13, 14: Реестр
$regPath = "HKCU:\Software\IDS_Test_Key"
if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force }
Set-ItemProperty -Path $regPath -Name "Val" -Value 1
Rename-Item -Path $regPath -NewName "IDS_Test_Renamed"
Remove-Item -Path "HKCU:\Software\IDS_Test_Renamed" -Force

# 17, 18: Pipes
$pipe = New-Object System.IO.Pipes.NamedPipeServerStream("MyTestPipe")
$pipe.Dispose()

# 10: Access (Нужен запуск от админа)
$lsass = Get-Process lsass
$handle = [Microsoft.Win32.SafeHandles.SafeProcessHandle]::new($lsass.Handle, $false)

Write-Host "--- ТЕСТ ЗАВЕРШЕН ---" -ForegroundColor Green