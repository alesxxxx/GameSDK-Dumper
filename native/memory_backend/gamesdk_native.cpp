#define WIN32_LEAN_AND_MEAN

#include "gamesdk_native.h"

#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <cwchar>
#include <memory>
#include <string>
#include <vector>

namespace {

constexpr uint64_t kMaxUserAddress = 0x00007FFFFFFFFFFFULL;
constexpr uint32_t kScanChunkSize = 0x100000;

bool is_readable_protect(DWORD protect) {
    if (protect == 0 || (protect & PAGE_GUARD)) {
        return false;
    }
    return (protect & 0xFF) != PAGE_NOACCESS;
}

HANDLE as_handle(uint64_t handle) {
    return reinterpret_cast<HANDLE>(static_cast<uintptr_t>(handle));
}

uint64_t as_u64(const void* ptr) {
    return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ptr));
}

void copy_wide(wchar_t* dst, size_t dst_count, const wchar_t* src) {
    if (!dst || dst_count == 0) {
        return;
    }
    dst[0] = L'\0';
    if (!src) {
        return;
    }
    wcsncpy_s(dst, dst_count, src, _TRUNCATE);
}

bool module_name_matches(const wchar_t* got, const wchar_t* expected) {
    if (!got || !expected) {
        return false;
    }
    return _wcsicmp(got, expected) == 0;
}

bool read_exact_or_partial(HANDLE handle, uint64_t address, uint8_t* out, uint32_t size, uint32_t* bytes_read) {
    if (bytes_read) {
        *bytes_read = 0;
    }
    if (!handle || !out || size == 0) {
        return false;
    }

    SIZE_T actual = 0;
    BOOL ok = ReadProcessMemory(
        handle,
        reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(address)),
        out,
        size,
        &actual);
    if (bytes_read) {
        *bytes_read = static_cast<uint32_t>(actual);
    }
    return ok || actual > 0;
}

bool match_pattern_at(
    const uint8_t* data,
    size_t offset,
    const GsdPatternByte* pattern,
    uint32_t pattern_len) {
    for (uint32_t i = 0; i < pattern_len; ++i) {
        if (pattern[i].mask && data[offset + i] != pattern[i].value) {
            return false;
        }
    }
    return true;
}

uint64_t fnv1a64(const uint8_t* data, size_t size) {
    uint64_t hash = 14695981039346656037ULL;
    for (size_t i = 0; i < size; ++i) {
        hash ^= static_cast<uint64_t>(data[i]);
        hash *= 1099511628211ULL;
    }
    return hash;
}

uint32_t fill_module_info(const MODULEENTRY32W& entry, GsdModuleInfo* out) {
    if (!out) {
        return GSD_INVALID_ARGUMENT;
    }
    copy_wide(out->name, GSDK_MAX_PATH_CHARS, entry.szModule);
    copy_wide(out->path, GSDK_MAX_PATH_CHARS, entry.szExePath);
    out->base = as_u64(entry.modBaseAddr);
    out->size = static_cast<uint64_t>(entry.modBaseSize);
    return GSD_OK;
}

} // namespace

GSDK_API uint32_t gsd_abi_version() {
    return GSDK_NATIVE_ABI_VERSION;
}

GSDK_API const wchar_t* gsd_backend_name() {
    return L"GameSDK Native User-Mode Backend";
}

GSDK_API uint64_t gsd_attach(uint32_t pid, uint32_t access, uint32_t* error_code) {
    if (error_code) {
        *error_code = 0;
    }

    HANDLE handle = OpenProcess(access, FALSE, pid);
    if (!handle) {
        if (error_code) {
            *error_code = GetLastError();
        }
        return 0;
    }
    return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(handle));
}

GSDK_API void gsd_detach(uint64_t handle) {
    if (handle) {
        CloseHandle(as_handle(handle));
    }
}

GSDK_API uint32_t gsd_read(
    uint64_t handle,
    uint64_t address,
    uint8_t* out,
    uint32_t size,
    uint32_t* bytes_read) {
    if (bytes_read) {
        *bytes_read = 0;
    }
    if (!handle || !out || size == 0) {
        return GSD_INVALID_ARGUMENT;
    }

    uint32_t actual = 0;
    if (!read_exact_or_partial(as_handle(handle), address, out, size, &actual)) {
        return GSD_ERROR;
    }
    if (bytes_read) {
        *bytes_read = actual;
    }
    return actual == size ? GSD_OK : GSD_PARTIAL;
}

GSDK_API uint32_t gsd_scatter_read(
    uint64_t handle,
    const GsdReadRequest* requests,
    uint32_t count,
    uint8_t* out,
    uint32_t stride,
    GsdReadResult* results) {
    if (!handle || !requests || !out || !results || count == 0 || stride == 0) {
        return GSD_INVALID_ARGUMENT;
    }

    uint32_t overall = GSD_OK;
    HANDLE process = as_handle(handle);
    for (uint32_t i = 0; i < count; ++i) {
        results[i].bytes_read = 0;
        results[i].status = GSD_ERROR;

        const uint32_t size = requests[i].size;
        if (size == 0 || size > stride) {
            results[i].status = GSD_INVALID_ARGUMENT;
            overall = GSD_PARTIAL;
            continue;
        }

        uint8_t* slot = out + (static_cast<size_t>(i) * stride);
        uint32_t actual = 0;
        if (!read_exact_or_partial(process, requests[i].address, slot, size, &actual)) {
            overall = GSD_PARTIAL;
            continue;
        }

        results[i].bytes_read = actual;
        results[i].status = actual == size ? GSD_OK : GSD_PARTIAL;
        if (results[i].status != GSD_OK) {
            overall = GSD_PARTIAL;
        }
    }
    return overall;
}

GSDK_API uint32_t gsd_enumerate_modules(
    uint32_t pid,
    GsdModuleInfo* out,
    uint32_t capacity) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    uint32_t total = 0;
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry)) {
        do {
            if (out && total < capacity) {
                fill_module_info(entry, &out[total]);
            }
            ++total;
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return total;
}

GSDK_API uint32_t gsd_get_module_info(
    uint32_t pid,
    const wchar_t* module_name,
    GsdModuleInfo* out) {
    if (!module_name || !out) {
        return GSD_INVALID_ARGUMENT;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return GSD_ERROR;
    }

    uint32_t status = GSD_NOT_FOUND;
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry)) {
        do {
            if (module_name_matches(entry.szModule, module_name)) {
                status = fill_module_info(entry, out);
                break;
            }
        } while (Module32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return status;
}

GSDK_API uint32_t gsd_iter_readable_regions(
    uint64_t handle,
    uint64_t start_address,
    GsdMemoryRegion* out,
    uint32_t capacity,
    uint64_t* next_address) {
    if (next_address) {
        *next_address = 0;
    }
    if (!handle || !out || capacity == 0) {
        return 0;
    }

    HANDLE process = as_handle(handle);
    uint64_t address = start_address;
    uint32_t count = 0;

    while (address <= kMaxUserAddress) {
        MEMORY_BASIC_INFORMATION mbi{};
        SIZE_T ok = VirtualQueryEx(
            process,
            reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(address)),
            &mbi,
            sizeof(mbi));
        if (ok == 0) {
            break;
        }

        const uint64_t base = as_u64(mbi.BaseAddress);
        const uint64_t size = static_cast<uint64_t>(mbi.RegionSize);
        if (size == 0) {
            break;
        }

        if (mbi.State == MEM_COMMIT && is_readable_protect(mbi.Protect)) {
            if (count >= capacity) {
                if (next_address) {
                    *next_address = base;
                }
                return count;
            }
            out[count].base = base;
            out[count].size = size;
            out[count].protect = mbi.Protect;
            out[count].type = mbi.Type;
            ++count;
        }

        const uint64_t next = base + size;
        if (next <= address) {
            break;
        }
        address = next;
    }

    if (next_address) {
        *next_address = 0;
    }
    return count;
}

GSDK_API uint32_t gsd_scan_pattern(
    uint64_t handle,
    uint64_t module_base,
    uint64_t module_size,
    const GsdPatternByte* pattern,
    uint32_t pattern_len,
    uint64_t* out_results,
    uint32_t max_results) {
    if (!handle || !pattern || !out_results || pattern_len == 0 || max_results == 0) {
        return 0;
    }

    HANDLE process = as_handle(handle);
    std::vector<uint8_t> buffer(kScanChunkSize + pattern_len);
    uint64_t offset = 0;
    uint32_t found = 0;
    const uint32_t overlap = pattern_len > 0 ? pattern_len - 1 : 0;

    while (offset < module_size && found < max_results) {
        const uint32_t to_read = static_cast<uint32_t>(
            std::min<uint64_t>(kScanChunkSize, module_size - offset));
        uint32_t actual = 0;
        if (!read_exact_or_partial(process, module_base + offset, buffer.data(), to_read, &actual) ||
            actual < pattern_len) {
            offset += to_read;
            continue;
        }

        const uint32_t search_end = actual - pattern_len + 1;
        for (uint32_t i = 0; i < search_end && found < max_results; ++i) {
            if (match_pattern_at(buffer.data(), i, pattern, pattern_len)) {
                out_results[found++] = module_base + offset + i;
            }
        }

        const uint32_t effective_overlap = std::min<uint32_t>(overlap, actual > 0 ? actual - 1 : 0);
        offset += actual - effective_overlap;
    }

    return found;
}

GSDK_API uint32_t gsd_resolve_rip(
    uint64_t handle,
    uint64_t match_address,
    uint32_t disp_offset,
    uint32_t instruction_size,
    uint64_t* target) {
    if (target) {
        *target = 0;
    }
    if (!handle || !target) {
        return GSD_INVALID_ARGUMENT;
    }

    uint8_t raw[4]{};
    uint32_t actual = 0;
    if (!read_exact_or_partial(as_handle(handle), match_address + disp_offset, raw, sizeof(raw), &actual) ||
        actual < sizeof(raw)) {
        return GSD_ERROR;
    }

    int32_t disp = 0;
    memcpy(&disp, raw, sizeof(disp));
    *target = static_cast<uint64_t>(static_cast<int64_t>(match_address + instruction_size) + disp);
    return GSD_OK;
}

GSDK_API uint32_t gsd_pe_fingerprint(
    uint64_t handle,
    uint64_t module_base,
    GsdPeFingerprint* out) {
    if (!handle || !out) {
        return GSD_INVALID_ARGUMENT;
    }
    *out = {};

    uint8_t dos_raw[sizeof(IMAGE_DOS_HEADER)]{};
    uint32_t actual = 0;
    if (!read_exact_or_partial(as_handle(handle), module_base, dos_raw, sizeof(dos_raw), &actual) ||
        actual < sizeof(dos_raw)) {
        return GSD_ERROR;
    }

    IMAGE_DOS_HEADER dos{};
    memcpy(&dos, dos_raw, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0) {
        return GSD_ERROR;
    }

    IMAGE_NT_HEADERS64 nt{};
    if (!read_exact_or_partial(
            as_handle(handle),
            module_base + static_cast<uint32_t>(dos.e_lfanew),
            reinterpret_cast<uint8_t*>(&nt),
            sizeof(nt),
            &actual) ||
        actual < offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + sizeof(IMAGE_OPTIONAL_HEADER32)) {
        return GSD_ERROR;
    }
    if (nt.Signature != IMAGE_NT_SIGNATURE) {
        return GSD_ERROR;
    }

    out->machine = nt.FileHeader.Machine;
    out->number_of_sections = nt.FileHeader.NumberOfSections;
    out->timestamp = nt.FileHeader.TimeDateStamp;
    out->size_of_image = nt.OptionalHeader.SizeOfImage;
    out->checksum = nt.OptionalHeader.CheckSum;
    out->entry_point_rva = nt.OptionalHeader.AddressOfEntryPoint;

    uint8_t header_sample[4096]{};
    uint32_t header_actual = 0;
    read_exact_or_partial(
        as_handle(handle),
        module_base,
        header_sample,
        sizeof(header_sample),
        &header_actual);
    out->header_fingerprint = fnv1a64(header_sample, header_actual);
    out->header_fingerprint ^= static_cast<uint64_t>(out->timestamp) << 32;
    out->header_fingerprint ^= static_cast<uint64_t>(out->size_of_image);
    return GSD_OK;
}
