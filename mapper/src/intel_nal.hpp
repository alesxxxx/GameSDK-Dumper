#pragma once
#include "driver_backend.hpp"
#include "nt_defs.hpp"
#include <Windows.h>
#include <string>
#include <vector>

namespace gsd {
    class IntelNalBackend : public IDriverBackend {
    private:
        HANDLE hDevice = INVALID_HANDLE_VALUE;
        uint64_t ntoskrnl_base = 0;
        std::wstring driver_path;
        std::wstring service_name;
        bool loaded = false;
        uint64_t fn_NtAddAtom = 0;
        uint8_t orig_NtAddAtom[12] = {};

        bool device_io(DWORD ioctl, void* in_buf, DWORD in_size, void* out_buf, DWORD out_size);
        bool mem_copy(uint64_t dst, uint64_t src, uint64_t size);
        bool acquire_debug_priv();
        bool acquire_load_driver_priv();
        bool cleanup_stale_helper_driver();
        bool clear_piddb();
        bool clear_hash_bucket();
        bool clear_mm_unloaded();
        bool clear_wdfilter();
        bool write_to_ro(uint64_t addr, const void* buf, uint32_t size);
        bool resolve_relative_addr_kernel(uint64_t instruction, ULONG offset_offset, ULONG instruction_size, uint64_t* out);
        bool find_MmAllocateIndependentPagesEx();
        bool find_MmFreeIndependentPages();
        bool find_MmSetPageProtection();
        uint64_t addr_MmAllocateIndependentPagesEx = 0;
        uint64_t addr_MmFreeIndependentPages = 0;
        uint64_t addr_MmSetPageProtection = 0;

    public:
        ~IntelNalBackend() override;
        bool load() override;
        bool unload() override;
        bool read(uint64_t addr, void* buf, uint64_t size) override;
        bool write(uint64_t addr, const void* buf, uint64_t size) override;
        bool read_ro(uint64_t addr, void* buf, uint32_t size) override;
        uint64_t allocate_pool(uint64_t size) override;
        bool free_pool(uint64_t addr) override;
        uint64_t allocate_independent_pages(uint32_t size) override;
        bool free_independent_pages(uint64_t addr, uint32_t size) override;
        bool set_page_protection(uint64_t addr, uint32_t size, ULONG prot) override;
        bool call_function(uint64_t fn_addr, uint64_t* out_result, const std::vector<uint64_t>& args) override;
        uint64_t resolve_export(uint64_t module_base, const std::string& name) override;
        uint64_t find_pattern_in_kernel_section(const char* section, uint64_t module_base, const uint8_t* mask, const char* pattern) override;
        uint64_t get_ntoskrnl_base() override;
        bool is_loaded() const override { return loaded; }
    };
}
