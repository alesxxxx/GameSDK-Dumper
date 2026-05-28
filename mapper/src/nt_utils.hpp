#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include "nt_defs.hpp"

namespace kutil {
    uint64_t get_kernel_module_base(const std::string& name);
    bool pattern_match(const BYTE* data, const BYTE* mask, const char* pattern);
    uint64_t find_pattern(uint64_t start, uint64_t len, const BYTE* mask, const char* pattern);
    uint64_t find_section(const char* name, uint64_t module_base, ULONG* size);
    PVOID resolve_relative_addr(PVOID instruction, ULONG offset_offset, ULONG instruction_size);
    std::wstring get_temp_path();
    bool write_file(const std::wstring& path, const void* data, size_t size);
    std::wstring random_name(int min_len = 10, int max_len = 30);
}
