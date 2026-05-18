@echo off
rem End-to-end build via CMake. Order:
rem   1. loader stub x64 -> stubs\stub_x64.bin
rem   2. loader stub x86 -> stubs\stub_x86.bin
rem   3. top-level scelot.exe (re-runs gen_embed.cmake to embed both blobs)
rem
rem No external prerequisites beyond cmake + Visual Studio 2022 with the
rem C++ workload (cl.exe, ml64.exe, ml.exe). VsDevCmd is NOT required -
rem CMake's "Visual Studio 17 2022" generator finds the toolchain itself.
setlocal EnableDelayedExpansion
set ROOT=%~dp0
pushd "%ROOT%"

where cmake >nul 2>nul || (echo [!] cmake not on PATH & popd & exit /b 1)
set GEN=Visual Studio 17 2022

echo === [1/3] loader stub x64 ===
cmake -S loader -B build\stub_x64 -G "%GEN%" -A x64 || goto :fail
cmake --build build\stub_x64 --config Release || goto :fail

echo === [2/3] loader stub x86 ===
cmake -S loader -B build\stub_x86 -G "%GEN%" -A Win32 || goto :fail
cmake --build build\stub_x86 --config Release || goto :fail

echo === [3/3] generator ===
cmake -S . -B build\main -G "%GEN%" -A x64 || goto :fail
cmake --build build\main --config Release || goto :fail

popd
echo.
echo OK - scelot.exe is in the project root.
exit /b 0

:fail
popd
echo FAILED
exit /b 1
