@echo off
setlocal
cl /nologo /O2 /Fe"%~dp0args_echo.exe" /Fo"%~dp0args_echo.obj" "%~dp0args_echo.c" /link /SUBSYSTEM:CONSOLE kernel32.lib
exit /b %ERRORLEVEL%
