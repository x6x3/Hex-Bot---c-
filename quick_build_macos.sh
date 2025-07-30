#!/bin/bash

if ! command -v cmake &> /dev/null; then
    echo "CMake not found! Install with: brew install cmake"
    exit 1
fi

if ! command -v git &> /dev/null; then
    echo "Git not found! Install Xcode Command Line Tools: xcode-select --install"
    exit 1
fi

mkdir -p build
cd build

if cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$(sysctl -n hw.ncpu); then
    echo "Build successful! Executable: build/hex-bot"
    cd ..
else
    cd ..
    ./build_macos.sh
fi

if [ -f "build/hex-bot" ]; then
    chmod +x build/hex-bot
else
    echo "Build failed!"
fi