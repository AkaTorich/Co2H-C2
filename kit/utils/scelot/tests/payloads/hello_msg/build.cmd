@echo off
setlocal
set ARCH=%1
if "%ARCH%"=="" set ARCH=x64
cl /nologo /O2 /Fe"%~dp0hello_msg.exe" /Fo"%~dp0hello_msg.obj" "%~dp0hello_msg.c" /link /SUBSYSTEM:WINDOWS user32.lib kernel32.lib
exit /b %ERRORLEVEL%
