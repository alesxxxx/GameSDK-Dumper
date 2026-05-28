#pragma once

#include <stdint.h>

#define GSDK_NATIVE_ABI_VERSION 1
#define GSDK_MAX_PATH_CHARS 260

#ifdef GSDK_NATIVE_EXPORTS
#define GSDK_API extern "C" __declspec(dllexport)
#else
#define GSDK_API extern "C" __declspec(dllimport)
#endif

enum GsdStatus : uint32_t {
    GSD_OK = 0,
    GSD_ERROR = 1,
    GSD_PARTIAL = 2,
    GSD_INVALID_ARGUMENT = 3,
    GSD_NOT_FOUND = 4,
};

struct GsdReadRequest {
    uint64_t address;
    uint32_t size;
    uint32_t reserved;
};

struct GsdReadResult {
    uint32_t bytes_read;
    uint32_t status;
};

struct GsdModuleInfo {
    wchar_t name[GSDK_MAX_PATH_CHARS];
    wchar_t path[GSDK_MAX_PATH_CHARS];
    uint64_t base;
    uint64_t size;
};

struct GsdMemoryRegion {
    uint64_t base;
    uint64_t size;
    uint32_t protect;
    uint32_t type;
};

struct GsdPatternByte {
    uint8_t value;
    uint8_t mask;
};

struct GsdPeFingerprint {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t timestamp;
    uint32_t size_of_image;
    uint32_t checksum;
    uint32_t entry_point_rva;
    uint64_t header_fingerprint;
};

GSDK_API uint32_t gsd_abi_version();
GSDK_API const wchar_t* gsd_backend_name();

GSDK_API uint64_t gsd_attach(uint32_t pid, uint32_t access, uint32_t* error_code);
GSDK_API void gsd_detach(uint64_t handle);

GSDK_API uint32_t gsd_read(
    uint64_t handle,
    uint64_t address,
    uint8_t* out,
    uint32_t size,
    uint32_t* bytes_read);

GSDK_API uint32_t gsd_scatter_read(
    uint64_t handle,
    const GsdReadRequest* requests,
    uint32_t count,
    uint8_t* out,
    uint32_t stride,
    GsdReadResult* results);

GSDK_API uint32_t gsd_enumerate_modules(
    uint32_t pid,
    GsdModuleInfo* out,
    uint32_t capacity);

GSDK_API uint32_t gsd_get_module_info(
    uint32_t pid,
    const wchar_t* module_name,
    GsdModuleInfo* out);

GSDK_API uint32_t gsd_iter_readable_regions(
    uint64_t handle,
    uint64_t start_address,
    GsdMemoryRegion* out,
    uint32_t capacity,
    uint64_t* next_address);

GSDK_API uint32_t gsd_scan_pattern(
    uint64_t handle,
    uint64_t module_base,
    uint64_t module_size,
    const GsdPatternByte* pattern,
    uint32_t pattern_len,
    uint64_t* out_results,
    uint32_t max_results);

GSDK_API uint32_t gsd_resolve_rip(
    uint64_t handle,
    uint64_t match_address,
    uint32_t disp_offset,
    uint32_t instruction_size,
    uint64_t* target);

GSDK_API uint32_t gsd_pe_fingerprint(
    uint64_t handle,
    uint64_t module_base,
    GsdPeFingerprint* out);
