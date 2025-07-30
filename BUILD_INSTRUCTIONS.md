# Build Instructions

## Windows

### Prerequisites
- Visual Studio 2019+ with C++ support
- Git
- CMake 3.15+

### Build
1. Run `quick_build_windows.bat`
2. Or manually:
```batch
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg && bootstrap-vcpkg.bat && cd ..
vcpkg\vcpkg install curl:x64-windows openssl:x64-windows boost:x64-windows nlohmann-json:x64-windows
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=..\vcpkg\scripts\buildsystems\vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows -A x64
cmake --build . --config Release
```

## macOS

### Prerequisites
- Xcode Command Line Tools: `xcode-select --install`
- Homebrew

### Build
1. Run `./quick_build_macos.sh`
2. Or manually:
```bash
brew install cmake curl openssl boost nlohmann-json
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=$(brew --prefix openssl) -DBOOST_ROOT=$(brew --prefix boost)
make -j$(sysctl -n hw.ncpu)
```

## Linux

### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install build-essential cmake libcurl4-openssl-dev libssl-dev libboost-all-dev nlohmann-json3-dev
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### CentOS/RHEL/Fedora
```bash
sudo dnf install gcc-c++ cmake libcurl-devel openssl-devel boost-devel nlohmann-json-devel
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

## Configuration

Before running, update `Hex-bot.c++`:
```cpp
const string BOT_TOKEN = "YOUR_BOT_TOKEN_HERE";
const string CONTACT_USERNAME = "@your_username";
vector<int64_t> ADMIN_USER_IDS = {your_user_id};
```

## Running

The bot creates JSON files automatically:
- `subs.json` - Subscriber data
- `keys.json` - Access keys
- `public_keys.json` - Public trial keys

Run the executable to start the bot.