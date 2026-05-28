#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <TlHelp32.h>

#include "logger.hpp"
#include "intel_nal.hpp"
#include "pe_mapper.hpp"
#include "nt_utils.hpp"

static LONG WINAPI crash_handler(EXCEPTION_POINTERS* info) {
    if (info && info->ExceptionRecord)
        gsd_log::err(L"Crash at " + gsd_log::hex_ptr(reinterpret_cast<uint64_t>(info->ExceptionRecord->ExceptionAddress))
            + L" code " + gsd_log::hex_u32(info->ExceptionRecord->ExceptionCode));
    else
        gsd_log::err(L"Unhandled exception.");
    return EXCEPTION_EXECUTE_HANDLER;
}

static bool arg_exists(const std::vector<std::wstring>& args, const wchar_t* name) {
    for (const auto& a : args) {
        if (a.length() >= 2 && a[0] == '-' && a[1] == '-') {
            if (_wcsicmp(a.c_str() + 2, name) == 0) return true;
        } else if (a.length() >= 1 && a[0] == '/') {
            if (_wcsicmp(a.c_str() + 1, name) == 0) return true;
        }
    }
    return false;
}

static DWORD get_parent_pid() {
    DWORD pid = GetCurrentProcessId();
    DWORD ppid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                ppid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return ppid;
}

static void pause_if_explorer() {
    DWORD explorer = 0;
    GetWindowThreadProcessId(GetShellWindow(), &explorer);
    if (get_parent_pid() == explorer) {
        gsd_log::info(L"Press Enter to exit...");
        std::wcin.get();
    }
}

int wmain(int argc, wchar_t** argv) {
    SetUnhandledExceptionFilter(crash_handler);

    std::vector<std::wstring> args(argv + 1, argv + argc);
    bool free_after = arg_exists(args, L"free");
    bool ind_pages = arg_exists(args, L"indPages");
    bool pass_alloc = arg_exists(args, L"passAlloc");
    bool keep_header = arg_exists(args, L"keepHeader");

    std::wstring driver_path;
    for (const auto& a : args) {
        if (a.size() > 4 && _wcsicmp(a.c_str() + a.size() - 4, L".sys") == 0) {
            driver_path = a;
            break;
        }
    }

    if (driver_path.empty() || !std::filesystem::exists(driver_path)) {
        gsd_log::err(L"Usage: gsd_mapper.exe [--free] [--indPages] [--passAlloc] [--keepHeader] driver.sys");
        pause_if_explorer();
        return 1;
    }

    if (free_after) gsd_log::detail(L"Free-after-exec enabled.");
    if (ind_pages) gsd_log::detail(L"Independent-pages allocation enabled.");
    if (pass_alloc) gsd_log::detail(L"Pass-allocation-as-first-param enabled.");
    if (keep_header) gsd_log::detail(L"Keeping PE header.");

    std::vector<uint8_t> raw_image;
    {
        std::ifstream f(driver_path, std::ios::binary | std::ios::ate);
        if (!f) {
            gsd_log::err(L"Cannot open driver image.");
            pause_if_explorer();
            return 1;
        }
        auto sz = f.tellg();
        f.seekg(0, std::ios::beg);
        raw_image.resize(static_cast<size_t>(sz));
        f.read(reinterpret_cast<char*>(raw_image.data()), sz);
    }

    gsd::IntelNalBackend backend;
    if (!backend.load()) {
        gsd_log::err(L"Failed to load driver backend.");
        pause_if_explorer();
        return 1;
    }

    gsd::AllocMode mode = ind_pages ? gsd::AllocMode::IndependentPages : gsd::AllocMode::Pool;
    auto result = gsd::map_driver(&backend, raw_image.data(), 0, 0, free_after, !keep_header, mode, pass_alloc);

    backend.unload();

    if (!result.success) {
        gsd_log::err(L"Driver mapping failed.");
        pause_if_explorer();
        return 1;
    }

    if (result.entry_status != 0) {
        gsd_log::warn(L"DriverEntry returned NTSTATUS " + gsd_log::hex_status(result.entry_status));
        pause_if_explorer();
        return 1;
    }

    gsd_log::info(L"Success.");
    pause_if_explorer();
    return 0;
}
