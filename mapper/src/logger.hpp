#pragma once
#include <Windows.h>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

namespace gsd_log {
    inline std::wstring hex_u64(uint64_t value, int width = 0) {
        std::wstringstream ss;
        ss << std::uppercase << std::hex << std::setfill(L'0');
        if (width > 0) {
            ss << std::setw(width);
        }
        ss << value;
        return ss.str();
    }

    inline std::wstring hex_ptr(uint64_t value) {
        return L"0x" + hex_u64(value, static_cast<int>(sizeof(void*) * 2));
    }

    inline std::wstring hex_u32(uint32_t value) {
        return L"0x" + hex_u64(value, 8);
    }

    inline std::wstring hex_status(NTSTATUS status) {
        return hex_u32(static_cast<uint32_t>(status));
    }

    inline void info(const std::wstring& msg) {
        std::wcout << L"[+] " << msg << std::endl;
    }
    inline void warn(const std::wstring& msg) {
        std::wcout << L"[!] " << msg << std::endl;
    }
    inline void err(const std::wstring& msg) {
        std::wcout << L"[-] " << msg << std::endl;
    }
    inline void detail(const std::wstring& msg) {
        std::wcout << L"[*] " << msg << std::endl;
    }
}
