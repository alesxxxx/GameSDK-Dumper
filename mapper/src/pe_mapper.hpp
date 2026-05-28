#pragma once
#include "driver_backend.hpp"
#include <cstdint>
#include <vector>
#include <string>

namespace gsd {
    enum class AllocMode {
        Pool,
        IndependentPages
    };

    struct MapResult {
        uint64_t base = 0;
        uint64_t real_base = 0;
        uint32_t image_size = 0;
        NTSTATUS entry_status = 0;
        bool success = false;
    };

    MapResult map_driver(IDriverBackend* backend, uint8_t* image, uint64_t param1, uint64_t param2,
                         bool free_after, bool keep_header, AllocMode mode, bool pass_alloc_as_first_param);
}
