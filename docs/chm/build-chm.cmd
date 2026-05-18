@echo off
REM Wrapper для build-chm.ps1 — выполняет конвертацию UTF-8 -> Windows-1251
REM (иначе CHM-просмотрщик показывает кракозябры на кириллице).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0build-chm.ps1"
exit /b %ERRORLEVEL%
