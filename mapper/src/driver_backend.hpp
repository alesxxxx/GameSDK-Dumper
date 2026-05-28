#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>
#include <functional>

namespace gsd {
    class IDriverBackend {
    public:
        virtual ~IDriverBackend() = default;
        virtual bool load() = 0;
        virtual bool unload() = 0;
        virtual bool read(uint64_t addr, void* buf, uint64_t size) = 0;
        virtual bool write(uint64_t addr, const void* buf, uint64_t size) = 0;
        virtual bool read_ro(uint64_t addr, void* buf, uint32_t size) = 0;
        virtual uint64_t allocate_pool(uint64_t size) = 0;
        virtual bool free_pool(uint64_t addr) = 0;
        virtual uint64_t allocate_independent_pages(uint32_t size) = 0;
        virtual bool free_independent_pages(uint64_t addr, uint32_t size) = 0;
        virtual bool set_page_protection(uint64_t addr, uint32_t size, ULONG prot) = 0;
        virtual bool call_function(uint64_t fn_addr, uint64_t* out_result, const std::vector<uint64_t>& args) = 0;
        virtual uint64_t resolve_export(uint64_t module_base, const std::string& name) = 0;
        virtual uint64_t find_pattern_in_kernel_section(const char* section, uint64_t module_base, const uint8_t* mask, const char* pattern) = 0;
        virtual uint64_t get_ntoskrnl_base() = 0;
        virtual bool is_loaded() const = 0;
    };
}
