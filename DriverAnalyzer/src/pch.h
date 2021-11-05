#pragma once

//
// Windows API headers
//

#pragma region Win32 API Headers

#define NOMINMAX
//#define CINTERFACE
#define _SCL_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winnt.h>
#include <tchar.h>
#include "shlwapi.h"
#pragma comment(lib, "Shlwapi.lib")

#pragma endregion = > Win32 API Headers

//
// std headers
//

#pragma region C++ Standrad Headers

#include <algorithm>
#include <numeric>
#include <chrono>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include <queue>
#include <mutex>
#include <future>

#include <optional>
#include <filesystem>
namespace fs = std::filesystem;

#pragma endregion = > C++ Standrad Headers

//
// third-party library headers
//

//
// cereal - A C++11 library for serialization
// vcpkg.exe install cereal:x64- indows cereal:x86-windows
//
#define USE_CEREAL_SERIALIZE
#ifdef USE_CEREAL_SERIALIZE
#    ifndef CINTERFACE
#        define CINTERFACE
#    endif

#    include <cereal/archives/json.hpp>
#    include <cereal/archives/xml.hpp>
#    include <cereal/types/string.hpp>
#    include <cereal/types/vector.hpp>

#    ifdef CINTERFACE
#        undef CINTERFACE
#    endif
#endif

//
// zydis - Fast and lightweight x86/x86-64 disassembler library https://zydis.re
// vcpkg.exe install zydis:x64-windows zydis:x86-windows
//

#include <Zydis/Utils.h>
#include <Zydis/Zydis.h>
#define MIN_FUNC_SIZE 0x20
#define MAX_FUNC_SIZE 0x100

// Lightweight C++ command line option parser
// vcpkg.exe install cxxopts : x64 - windows cxxopts : x86 - windows
#include <cxxopts.hpp>

//
// LIEF
//
#pragma warning(push)
#pragma warning(disable : 4146)  // C4146: unary minus operator applied to \
                                 // unsigned type, result still unsigned
#pragma warning(disable : 4996)
#pragma warning(disable : 4267)

#include <LIEF/LIEF.hpp>

#pragma comment(lib, "LIEF.lib")

#pragma warning(pop)

#include "utils/utils.h"