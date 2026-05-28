#pragma once
#include <Windows.h>
#include <string>

namespace svc_mgr {
    bool register_and_start(const std::wstring& driver_path, const std::wstring& service_name);
    bool stop_and_remove(const std::wstring& service_name);
}
