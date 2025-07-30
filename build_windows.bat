@echo off

if not exist "vcpkg" (
    git clone https://github.com/Microsoft/vcpkg.git
    cd vcpkg
    call bootstrap-vcpkg.bat
    cd ..
)

vcpkg\vcpkg install curl:x64-windows
vcpkg\vcpkg install openssl:x64-windows
vcpkg\vcpkg install boost:x64-windows
vcpkg\vcpkg install nlohmann-json:x64-windows

if not exist "build" mkdir build
cd build

cmake .. -DCMAKE_TOOLCHAIN_FILE=..\vcpkg\scripts\buildsystems\vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows -A x64

cmake --build . --config Release