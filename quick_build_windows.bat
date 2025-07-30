@echo off

where cmake >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo CMake not found! Install from: https://cmake.org/download/
    pause
    exit /b 1
)

where git >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Git not found! Install from: https://git-scm.com/download/win
    pause
    exit /b 1
)

if not exist "build" mkdir build
cd build

cmake .. -DCMAKE_BUILD_TYPE=Release
if %ERRORLEVEL% EQU 0 (
    cmake --build . --config Release
    if %ERRORLEVEL% EQU 0 (
        echo Build successful! Executable: build\Release\hex-bot.exe
        cd ..
        goto :end
    )
)

cd ..
call build_windows.bat

:end
pause