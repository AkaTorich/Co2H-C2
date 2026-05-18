@echo off
setlocal
cl /nologo /O2 /LD /Fe"%~dp0dll_run.dll" /Fo"%~dp0dll_run.obj" "%~dp0dll_run.c" /link /EXPORT:Run user32.lib kernel32.lib
exit /b %ERRORLEVEL%
