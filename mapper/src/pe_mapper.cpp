#include "pe_mapper.hpp"
#include "logger.hpp"
#include "nt_utils.hpp"
#include <Windows.h>
#include <vector>
#include <cstring>

static PIMAGE_NT_HEADERS64 get_nt_headers(void* base) {
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<uint8_t*>(base) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    return nt;
}

static bool fix_cookie(void* local_base, uint64_t kernel_base) {
    auto* nt = get_nt_headers(local_base);
    if (!nt) return false;
    auto& lc = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (!lc.VirtualAddress) return true; // no load config = no cookie to fix
    if (lc.VirtualAddress >= nt->OptionalHeader.SizeOfImage ||
        lc.VirtualAddress + sizeof(IMAGE_LOAD_CONFIG_DIRECTORY) > nt->OptionalHeader.SizeOfImage) {
        gsd_log::err(L"Load config directory is outside the local image.");
        return false;
    }

    auto* cfg = reinterpret_cast<PIMAGE_LOAD_CONFIG_DIRECTORY>(reinterpret_cast<uint8_t*>(local_base) + lc.VirtualAddress);
    if (!cfg->SecurityCookie) return true;

    if (cfg->SecurityCookie < kernel_base ||
        cfg->SecurityCookie + sizeof(uint64_t) < cfg->SecurityCookie ||
        cfg->SecurityCookie + sizeof(uint64_t) > kernel_base + nt->OptionalHeader.SizeOfImage) {
        gsd_log::err(L"Security cookie address is outside the mapped image.");
        return false;
    }

    uint64_t cookie_rva = cfg->SecurityCookie - kernel_base;
    uint64_t* cookie_ptr = reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(local_base) + cookie_rva);
    if (*cookie_ptr != 0x2B992DDFA232ULL) {
        gsd_log::warn(L"Security cookie already modified — suspicious.");
        return false;
    }
    uint64_t new_cookie = 0x2B992DDFA232ULL ^ GetCurrentProcessId() ^ GetCurrentThreadId();
    if (new_cookie == 0x2B992DDFA232ULL) new_cookie = 0x2B992DDFA233ULL;
    *cookie_ptr = new_cookie;
    return true;
}

static bool resolve_imports(gsd::IDriverBackend* backend, void* local_base, uint64_t kernel_base) {
    auto* nt = get_nt_headers(local_base);
    if (!nt) return false;
    auto& imp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!imp_dir.VirtualAddress) return true;

    auto* imp_desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<uint8_t*>(local_base) + imp_dir.VirtualAddress);
    uint64_t ntos_base = backend->get_ntoskrnl_base();

    while (imp_desc->Name) {
        const char* dll_name = reinterpret_cast<const char*>(reinterpret_cast<uint8_t*>(local_base) + imp_desc->Name);
        uint64_t dll_base = kutil::get_kernel_module_base(dll_name);
        if (!dll_base) {
            // Try ntoskrnl fallback (for HAL.dll forwarded exports)
            dll_base = ntos_base;
        }

        auto* thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<uint8_t*>(local_base) + imp_desc->FirstThunk);
        auto* orig_thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<uint8_t*>(local_base) + imp_desc->OriginalFirstThunk);

        while (thunk->u1.AddressOfData) {
            uint64_t fn_addr = 0;
            if (IMAGE_SNAP_BY_ORDINAL64(orig_thunk->u1.Ordinal)) {
                // import by ordinal — try primary dll, fallback ntos
                fn_addr = backend->resolve_export(dll_base, ""); // can't resolve by ordinal easily with our helper
                if (!fn_addr && dll_base != ntos_base) fn_addr = backend->resolve_export(ntos_base, "");
            } else {
                auto* by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<uint8_t*>(local_base) + orig_thunk->u1.AddressOfData);
                fn_addr = backend->resolve_export(dll_base, by_name->Name);
                if (!fn_addr && dll_base != ntos_base) fn_addr = backend->resolve_export(ntos_base, by_name->Name);
            }
            if (!fn_addr) {
                gsd_log::err(std::wstring(L"Failed to resolve import: ") + std::wstring(dll_name, dll_name + strlen(dll_name)));
                return false;
            }
            thunk->u1.Function = fn_addr;
            ++thunk;
            ++orig_thunk;
        }
        ++imp_desc;
    }
    return true;
}

static void apply_relocs(void* local_base, uint64_t kernel_base, int64_t delta) {
    auto* nt = get_nt_headers(local_base);
    if (!nt) return;
    auto& reloc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!reloc_dir.VirtualAddress) return;

    auto* reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uint8_t*>(local_base) + reloc_dir.VirtualAddress);
    while (reloc->VirtualAddress) {
        ULONG num_entries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        auto* entries = reinterpret_cast<PWORD>(reinterpret_cast<uint8_t*>(reloc) + sizeof(IMAGE_BASE_RELOCATION));
        for (ULONG i = 0; i < num_entries; ++i) {
            WORD type = (entries[i] >> 12) & 0xF;
            WORD offset = entries[i] & 0xFFF;
            if (type == IMAGE_REL_BASED_DIR64) {
                auto* ptr = reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(local_base) + reloc->VirtualAddress + offset);
                *ptr += delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                auto* ptr = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(local_base) + reloc->VirtualAddress + offset);
                *ptr += static_cast<uint32_t>(delta);
            }
        }
        reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uint8_t*>(reloc) + reloc->SizeOfBlock);
    }
}

gsd::MapResult gsd::map_driver(IDriverBackend* backend, uint8_t* image, uint64_t param1, uint64_t param2,
                               bool free_after, bool keep_header, AllocMode mode, bool pass_alloc_as_first_param) {
    MapResult res = {};
    if (!backend || !image) return res;

    auto* nt = get_nt_headers(image);
    if (!nt) {
        gsd_log::err(L"Invalid PE image.");
        return res;
    }
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        gsd_log::err(L"Image is not 64-bit.");
        return res;
    }

    ULONG image_size = nt->OptionalHeader.SizeOfImage;
    DWORD header_skip = IMAGE_FIRST_SECTION(nt)->VirtualAddress;
    ULONG alloc_size = image_size - (keep_header ? 0 : header_skip);

    uint64_t kernel_base = 0;
    if (mode == AllocMode::IndependentPages) {
        kernel_base = backend->allocate_independent_pages(alloc_size);
    } else {
        kernel_base = backend->allocate_pool(alloc_size);
    }
    if (!kernel_base) {
        gsd_log::err(L"Failed to allocate kernel memory.");
        return res;
    }

    gsd_log::info(L"Kernel image allocated at " + gsd_log::hex_ptr(kernel_base));

    gsd_log::detail(L"Preparing local PE image...");
    void* local_buf = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!local_buf) {
        gsd_log::err(L"Failed to allocate local image buffer.");
        if (mode == AllocMode::IndependentPages) backend->free_independent_pages(kernel_base, alloc_size);
        else backend->free_pool(kernel_base);
        return res;
    }

    memcpy(local_buf, image, nt->OptionalHeader.SizeOfHeaders);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (sec[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) continue;
        void* dst = reinterpret_cast<uint8_t*>(local_buf) + sec[i].VirtualAddress;
        void* src = image + sec[i].PointerToRawData;
        memcpy(dst, src, sec[i].SizeOfRawData);
    }

    uint64_t real_base = kernel_base;
    if (!keep_header) {
        kernel_base -= header_skip;
    }

    int64_t delta = static_cast<int64_t>(kernel_base) - static_cast<int64_t>(nt->OptionalHeader.ImageBase);
    gsd_log::detail(L"Applying relocations...");
    apply_relocs(local_buf, kernel_base, delta);

    gsd_log::detail(L"Fixing security cookie...");
    if (!fix_cookie(local_buf, kernel_base)) {
        gsd_log::err(L"Security cookie fix failed.");
        VirtualFree(local_buf, 0, MEM_RELEASE);
        if (mode == AllocMode::IndependentPages) backend->free_independent_pages(real_base, alloc_size);
        else backend->free_pool(real_base);
        return res;
    }

    gsd_log::detail(L"Resolving imports...");
    if (!resolve_imports(backend, local_buf, kernel_base)) {
        gsd_log::err(L"Import resolution failed.");
        VirtualFree(local_buf, 0, MEM_RELEASE);
        if (mode == AllocMode::IndependentPages) backend->free_independent_pages(real_base, alloc_size);
        else backend->free_pool(real_base);
        return res;
    }

    uint8_t* write_src = reinterpret_cast<uint8_t*>(local_buf) + (keep_header ? 0 : header_skip);
    gsd_log::detail(L"Writing mapped image to kernel memory...");
    if (!backend->write(real_base, write_src, alloc_size)) {
        gsd_log::err(L"Failed to write image to kernel memory.");
        VirtualFree(local_buf, 0, MEM_RELEASE);
        if (mode == AllocMode::IndependentPages) backend->free_independent_pages(real_base, alloc_size);
        else backend->free_pool(real_base);
        return res;
    }

    if (mode == AllocMode::IndependentPages) {
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            auto& s = sec[i];
            if (s.Misc.VirtualSize == 0) continue;
            uint64_t sec_addr = kernel_base + s.VirtualAddress;
            ULONG prot = PAGE_READONLY;
            if (s.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                prot = (s.Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
            } else if (s.Characteristics & IMAGE_SCN_MEM_WRITE) {
                prot = PAGE_READWRITE;
            }
            backend->set_page_protection(sec_addr, s.Misc.VirtualSize, prot);
        }
    }

    uint64_t entry_point = kernel_base + nt->OptionalHeader.AddressOfEntryPoint;
    gsd_log::detail(L"Calling DriverEntry at " + gsd_log::hex_ptr(entry_point));

    uint64_t first_param = pass_alloc_as_first_param ? real_base : param1;
    NTSTATUS status = 0;
    backend->call_function(entry_point, reinterpret_cast<uint64_t*>(&status), { first_param, param2 });

    gsd_log::info(L"DriverEntry returned " + gsd_log::hex_status(status));

    VirtualFree(local_buf, 0, MEM_RELEASE);

    if (free_after) {
        gsd_log::detail(L"Freeing kernel memory...");
        bool freed = (mode == AllocMode::IndependentPages)
            ? backend->free_independent_pages(real_base, alloc_size)
            : backend->free_pool(real_base);
        if (freed) gsd_log::info(L"Memory freed.");
        else gsd_log::warn(L"Failed to free kernel memory.");
    }

    res.base = kernel_base;
    res.real_base = real_base;
    res.image_size = alloc_size;
    res.entry_status = status;
    res.success = true;
    return res;
}
