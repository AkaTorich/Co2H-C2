@echo off
rem Builds NetHello.exe using the .NET Framework 4.x csc.exe.
setlocal
set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe
"%CSC%" /nologo /target:exe /out:"%~dp0NetHello.exe" "%~dp0NetHello.cs"
exit /b %ERRORLEVEL%
