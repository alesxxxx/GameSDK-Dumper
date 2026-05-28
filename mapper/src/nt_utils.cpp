#include "nt_utils.hpp"
#include <Windows.h>
#include <winternl.h>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <vector>

uint64_t kutil::get_kernel_module_base(const std::string& name) {
    ULONG req = 0;
    NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)ntdefs::SystemModuleInformation, nullptr, 0, &req);
    if (status != STATUS_INFO_LENGTH_MISMATCH) return 0;

    std::vector<BYTE> buffer(req);
    status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)ntdefs::SystemModuleInformation, buffer.data(), req, &req);
    if (!NT_SUCCESS(status)) return 0;

    auto mods = reinterpret_cast<ntdefs::PRTL_PROCESS_MODULES>(buffer.data());
    for (ULONG i = 0; i < mods->NumberOfModules; ++i) {
        auto& m = mods->Modules[i];
        char* fname = reinterpret_cast<char*>(m.FullPathName + m.OffsetToFileName);
        if (_stricmp(fname, name.c_str()) == 0) {
            return reinterpret_cast<uint64_t>(m.ImageBase);
        }
    }
    return 0;
}

bool kutil::pattern_match(const BYTE* data, const BYTE* mask, const char* pattern) {
    for (; *pattern; ++pattern, ++data, ++mask) {
        if (*pattern == 'x' && *data != *mask) return false;
    }
    return true;
}

uint64_t kutil::find_pattern(uint64_t start, uint64_t len, const BYTE* mask, const char* pattern) {
    size_t pat_len = strlen(pattern);
    if (!start || !len || !pat_len || len < pat_len) return 0;
    for (size_t i = 0; i <= len - pat_len; ++i) {
        if (pattern_match(reinterpret_cast<const BYTE*>(start + i), mask, pattern))
            return start + i;
    }
    return 0;
}

uint64_t kutil::find_section(const char* name, uint64_t module_base, ULONG* size) {
    if (!module_base) return 0;
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(module_base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(module_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    auto section = IMAGE_FIRST_SECTION(nt);
    size_t name_len = strlen(name);
    for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        char section_name[IMAGE_SIZEOF_SHORT_NAME + 1] = {};
        memcpy(section_name, section->Name, IMAGE_SIZEOF_SHORT_NAME);
        if (strlen(section_name) == name_len && memcmp(section_name, name, name_len) == 0) {
            if (size) *size = section->Misc.VirtualSize;
            return module_base + section->VirtualAddress;
        }
    }
    return 0;
}

PVOID kutil::resolve_relative_addr(PVOID instruction, ULONG offset_offset, ULONG instruction_size) {
    LONG rip_offset = 0;
    memcpy(&rip_offset, reinterpret_cast<PBYTE>(instruction) + offset_offset, sizeof(LONG));
    return reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(instruction) + instruction_size + rip_offset);
}

std::wstring kutil::get_temp_path() {
    wchar_t buf[MAX_PATH] = {};
    DWORD len = GetTempPathW(MAX_PATH, buf);
    if (!len || len > MAX_PATH) return L"";
    std::wstring path(buf);
    while (path.length() > 3 && (path.back() == L'\\' || path.back() == L'/')) {
        path.pop_back();
    }
    return path;
}

bool kutil::write_file(const std::wstring& path, const void* data, size_t size) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(data), size);
    return f.good();
}

std::wstring kutil::random_name(int min_len, int max_len) {
    static bool seeded = false;
    if (!seeded) { srand(static_cast<unsigned>(time(nullptr)) ^ GetCurrentThreadId()); seeded = true; }
    const char alphanum[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int len = min_len + (rand() % (max_len - min_len + 1));
    std::string s;
    for (int i = 0; i < len; ++i) s.push_back(alphanum[rand() % (sizeof(alphanum) - 1)]);
    return std::wstring(s.begin(), s.end());
}
