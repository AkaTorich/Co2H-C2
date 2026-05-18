@echo off
rem Builds scelot_gui.exe with the system C# 4.x compiler.
rem No csproj, no MSBuild — just csc.exe + Windows Forms.
setlocal
cd /d "%~dp0"
set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe
"%CSC%" /nologo /target:winexe /out:scelot_gui.exe ^
    /reference:System.dll ^
    /reference:System.Drawing.dll ^
    /reference:System.Windows.Forms.dll ^
    scelot_gui.cs
exit /b %ERRORLEVEL%
