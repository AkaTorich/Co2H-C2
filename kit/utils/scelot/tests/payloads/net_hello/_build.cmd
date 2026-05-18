@echo off
cd /d "%~dp0"
"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /target:exe /out:NetHello.exe NetHello.cs
exit /b %ERRORLEVEL%
