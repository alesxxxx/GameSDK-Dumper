#include "service_mgr.hpp"
#include "logger.hpp"
#include <windows.h>
#include <string>

bool svc_mgr::register_and_start(const std::wstring& driver_path, const std::wstring& service_name) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        gsd_log::err(L"OpenSCManagerW failed: " + std::to_wstring(GetLastError()));
        return false;
    }

    SC_HANDLE svc = CreateServiceW(
        scm,
        service_name.c_str(),
        service_name.c_str(),
        SERVICE_START | SERVICE_STOP | DELETE,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        driver_path.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr
    );

    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            svc = OpenServiceW(scm, service_name.c_str(), SERVICE_START | SERVICE_STOP | DELETE);
        }
        if (!svc) {
            gsd_log::err(L"CreateServiceW/OpenServiceW failed: " + std::to_wstring(err));
            CloseServiceHandle(scm);
            return false;
        }
    }

    bool ok = StartServiceW(svc, 0, nullptr);
    if (!ok) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            gsd_log::err(L"StartServiceW failed: " + std::to_wstring(err));
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return false;
        }
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return true;
}

bool svc_mgr::stop_and_remove(const std::wstring& service_name) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceW(scm, service_name.c_str(), SERVICE_STOP | DELETE);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS status{};
    ControlService(svc, SERVICE_CONTROL_STOP, &status);
    DeleteService(svc);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return true;
}
