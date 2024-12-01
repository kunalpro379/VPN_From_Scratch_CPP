#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <codecvt>
#include <locale>

// TAP-Windows device GUID and related constants
#define TAP_WINDOWS_GUID "tap0901"
#define TAP_IOCTL_GET_MAC               TAP_CONTROL_CODE(1, METHOD_BUFFERED)
#define TAP_IOCTL_GET_VERSION           TAP_CONTROL_CODE(2, METHOD_BUFFERED)
#define TAP_IOCTL_SET_MEDIA_STATUS      TAP_CONTROL_CODE(6, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_TUN            TAP_CONTROL_CODE(10, METHOD_BUFFERED)
#define TAP_CONTROL_CODE(request,method) CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
#define TAP_IOCTL_GET_MEDIA_STATUS      TAP_CONTROL_CODE(3, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_CONFIG_TUN TAP_CONTROL_CODE(10, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT TAP_CONTROL_CODE(11, METHOD_BUFFERED)
typedef ULONG IPAddr;

class TunDevice {
private:
    HANDLE deviceHandle;
    std::wstring devicePath;
    bool isConnected;
    
    // Helper function to convert string to wstring
    std::wstring stringToWString(const std::string& str) {
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        return converter.from_bytes(str);
    }


/*
    // Helper function to find TAP device GUID
std::wstring findTapDevice() {
    HKEY adaptersKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}",
        0, KEY_READ, &adaptersKey) != ERROR_SUCCESS) {
        throw std::runtime_error("Failed to open network adapters registry key");
    }

    wchar_t valueName[256];
    DWORD valueNameSize;
    DWORD index = 0;
    std::wstring openvpnPath;  // Store OpenVPN TAP path
    std::wstring fallbackPath; // Store first TAP path as fallback

    while (true) {
        valueNameSize = sizeof(valueName) / sizeof(wchar_t);
        if (RegEnumKeyExW(adaptersKey, index, valueName, &valueNameSize,
            NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
            break;
        }

        HKEY adapterKey;
        std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\" + std::wstring(valueName);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_READ, &adapterKey) == ERROR_SUCCESS) {
            wchar_t componentId[256];
            DWORD dataSize = sizeof(componentId);
            
            if (RegQueryValueExW(adapterKey, L"ComponentId", NULL, NULL, (LPBYTE)componentId, &dataSize) == ERROR_SUCCESS) {
                std::wstring componentIdStr(componentId);
                if (componentIdStr.find(stringToWString(TAP_WINDOWS_GUID)) != std::wstring::npos) {
                    // Found a TAP adapter, now check if it's OpenVPN
                    wchar_t driverDesc[256];
                    dataSize = sizeof(driverDesc);
                    if (RegQueryValueExW(adapterKey, L"DriverDesc", NULL, NULL, (LPBYTE)driverDesc, &dataSize) == ERROR_SUCCESS) {
                        std::wstring driverDescStr(driverDesc);
                        
                        wchar_t netCfgInstanceId[256];
                        dataSize = sizeof(netCfgInstanceId);
                        if (RegQueryValueExW(adapterKey, L"NetCfgInstanceId", NULL, NULL,
                            (LPBYTE)netCfgInstanceId, &dataSize) == ERROR_SUCCESS) {
                            std::wstring path = L"\\\\.\\Global\\" + std::wstring(netCfgInstanceId) + L".tap";
                            
                            // Check if this is the OpenVPN adapter
                            if (driverDescStr.find(L"OpenVPN") != std::wstring::npos) {
                                openvpnPath = path;
                            } else if (fallbackPath.empty()) {
                                fallbackPath = path;
                            }
                        }
                    }
                }
            }
            RegCloseKey(adapterKey);
        }
        index++;
    }
    RegCloseKey(adaptersKey);

    // Prefer OpenVPN TAP adapter if found
    if (!openvpnPath.empty()) {
        std::wcout << L"Using OpenVPN TAP adapter: " << openvpnPath << std::endl;
        return openvpnPath;
    }
    
    // Fall back to any other TAP adapter
    if (!fallbackPath.empty()) {
        std::wcout << L"No OpenVPN TAP adapter found, using fallback: " << fallbackPath << std::endl;
        return fallbackPath;
    }

    throw std::runtime_error("No TAP device found");
}

*/
    std::wstring findTapDevice() {
        // Directly use the OpenVPN TAP-Windows6 adapter
        std::wstring path = L"\\\\.\\Global\\{9848B1C0-704B-42D1-81AA-78947DBF323D}.tap";
        std::wcout << L"Using OpenVPN TAP-Windows6 adapter: " << path << std::endl;
        return path;
    }
public:
    TunDevice() : deviceHandle(INVALID_HANDLE_VALUE), isConnected(false) {
        try {
            devicePath = findTapDevice();
        } catch (const std::runtime_error& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            throw;
        }
    }

     bool create() {
        std::wcout << L"Opening TAP device at: " << devicePath << std::endl;
        deviceHandle = CreateFileW(
            devicePath.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            0,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
            0);

        if (deviceHandle == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            std::cerr << "Failed to create TUN device. Error code: " << error << std::endl;
            wchar_t errorMsg[256];
            FormatMessageW(
                FORMAT_MESSAGE_FROM_SYSTEM,
                NULL,
                error,
                0,
                errorMsg,
                sizeof(errorMsg)/sizeof(wchar_t),
                NULL
            );
            std::wcerr << L"Error message: " << errorMsg << std::endl;
            return false;
        }

        std::cout << "Successfully opened TAP device" << std::endl;
        return true;
    }
bool configure(const std::string& ip, const std::string& netmask) {
    // First set media status
    ULONG status = 1;
    DWORD len;
    if (!DeviceIoControl(deviceHandle, TAP_IOCTL_SET_MEDIA_STATUS,
        &status, sizeof(status),
        &status, sizeof(status),
        &len, NULL)) {
        DWORD error = GetLastError();
        std::cerr << "Failed to set media status. Error: " << error << std::endl;
        return false;
    }

    // Configure TUN interface
    struct {
        ULONG network;
        ULONG netmask;
        ULONG local;
        ULONG remote;
    } tun_config;

    // Convert IP addresses to network byte order
    struct in_addr addr;
    
    // Set network address (0.0.0.0)
    addr.s_addr = htonl(0);
    tun_config.network = addr.s_addr;
    
    // Set netmask
    if (inet_pton(AF_INET, netmask.c_str(), &addr) != 1) {
        std::cerr << "Failed to convert netmask" << std::endl;
        return false;
    }
    tun_config.netmask = addr.s_addr;
    
    // Set local IP
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        std::cerr << "Failed to convert local IP" << std::endl;
        return false;
    }
    tun_config.local = addr.s_addr;
    
    // Set remote address (0.0.0.0)
    addr.s_addr = htonl(0);
    tun_config.remote = addr.s_addr;

    // Debug output
    char debug_ip[INET_ADDRSTRLEN];
    std::cout << "TUN Configuration (network byte order):" << std::endl;
    std::cout << "Network: 0x" << std::hex << ntohl(tun_config.network) << std::endl;
    std::cout << "Netmask: 0x" << std::hex << ntohl(tun_config.netmask) << std::endl;
    std::cout << "Local: 0x" << std::hex << ntohl(tun_config.local) << std::endl;
    std::cout << "Remote: 0x" << std::hex << ntohl(tun_config.remote) << std::dec << std::endl;

    // Try configuring as point-to-point first
    if (!DeviceIoControl(deviceHandle, TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT,
        &tun_config, sizeof(tun_config),
        &tun_config, sizeof(tun_config),
        &len, NULL)) {
        DWORD error = GetLastError();
        std::cout << "Point-to-point configuration failed, trying TUN mode. Error: " << error << std::endl;
        
        // If point-to-point fails, try TUN mode
        if (!DeviceIoControl(deviceHandle, TAP_WIN_IOCTL_CONFIG_TUN,
            &tun_config, sizeof(tun_config),
            &tun_config, sizeof(tun_config),
            &len, NULL)) {
            error = GetLastError();
            std::cerr << "Failed to configure TUN. Error: " << error << std::endl;
            return false;
        }
    }

    isConnected = true;
    std::cout << "TUN interface configured successfully" << std::endl;
    return true;
}
    bool verifyTunDevice() {
        std::cout << "\nVerifying TUN device status..." << std::endl;
        
        // 1. Check if device handle is valid
        if (deviceHandle == INVALID_HANDLE_VALUE) {
            std::cerr << "Device handle is invalid" << std::endl;
            return false;
        }
        std::cout << "✓ Device handle is valid" << std::endl;

        // 2. Get interface name
        std::wstring interfaceName = devicePath.substr(11, devicePath.length() - 15);
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        std::string interfaceNameStr = converter.to_bytes(interfaceName);

        // 3. Check interface status using ipconfig (with more specific filtering)
        {
            // First, get all network adapters
            std::string cmd = "wmic nic get Name,NetConnectionStatus /format:list | findstr /i \"" + interfaceNameStr + "\"";
            FILE* pipe = _popen(cmd.c_str(), "r");
            if (pipe) {
                char buffer[256];
                std::cout << "\nAdapter Status:" << std::endl;
                while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                    std::cout << buffer;
                }
                _pclose(pipe);
            }
        }

        // 4. Check IP configuration
        {
            std::string cmd = "wmic nicconfig where \"SettingID='" + interfaceNameStr + "'\" get IPAddress,IPSubnet /format:list";
            FILE* pipe = _popen(cmd.c_str(), "r");
            if (pipe) {
                char buffer[256];
                std::cout << "\nIP Configuration:" << std::endl;
                while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                    std::cout << buffer;
                }
                _pclose(pipe);
            }
        }

        // 5. Check media status using DeviceIoControl
        ULONG status;
        DWORD len;
        if (DeviceIoControl(deviceHandle, TAP_IOCTL_GET_MEDIA_STATUS,
            &status, sizeof(status),
            &status, sizeof(status),
            &len, NULL)) {
            std::cout << "\nTAP Device Status:" << std::endl;
            std::cout << "Media Status: " << (status ? "Connected" : "Disconnected") << std::endl;
        }

        // 6. Check if interface is in network connections
        {
            std::string cmd = "powershell -Command \"Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*TAP-Windows*' } | Format-List\"";
            FILE* pipe = _popen(cmd.c_str(), "r");
            if (pipe) {
                char buffer[256];
                std::cout << "\nDetailed Adapter Information:" << std::endl;
                while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                    std::cout << buffer;
                }
                _pclose(pipe);
            }
        }

        std::cout << "\nTUN device verification complete" << std::endl;
        return true;
    }

  bool bringUp() {
        if (!isConnected) {
            std::cerr << "Device not configured" << std::endl;
            return false;
        }

        // Get the interface name from the device path
        // Remove the "\\.\\Global\\" prefix and ".tap" suffix
        std::wstring interfaceName = devicePath.substr(11, devicePath.length() - 15);
        
        // Convert to narrow string for system command
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        std::string interfaceNameStr = converter.to_bytes(interfaceName);

        std::cout << "Bringing up interface: " << interfaceNameStr << std::endl;
        
        // Try multiple commands to ensure the interface is properly enabled
        std::vector<std::string> commands = {
          
            // "netsh interface set interface interface=\"" + interfaceNameStr + "\" admin=enabled"     
            "netsh interface set interface name=\"OpenVPN TAP-Windows6\" admin=enabled"

               };

        for (const auto& cmd : commands) {
            std::cout << "Trying command: " << cmd << std::endl;
            int result = system(cmd.c_str());
            if (result == 0) {
                std::cout << "Interface enabled successfully" << std::endl;
                return true;
            }
            std::cout << "Command failed with code: " << result << std::endl;
        }

        // If we get here, none of the commands worked
        std::cerr << "Failed to bring up interface after trying all commands" << std::endl;
        
        // Try to get more detailed error information
        DWORD error = GetLastError();
        wchar_t errorMsg[256];
        FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM,
            NULL,
            error,
            0,
            errorMsg,
            sizeof(errorMsg)/sizeof(wchar_t),
            NULL
        );
        std::wcerr << L"System error message: " << errorMsg << std::endl;
        
        return false;
    }

    void close() {
        if (deviceHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(deviceHandle);
            deviceHandle = INVALID_HANDLE_VALUE;
        }
        isConnected = false;
    }

    ~TunDevice() {
        close();
    }

    HANDLE getHandle() const { return deviceHandle; }
};

// Example usage
int main() {
    try {
        TunDevice tun;
        BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;

        if (AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &AdministratorsGroup)) {
        CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin);
        FreeSid(AdministratorsGroup);
    }

    if (!isAdmin) {
        std::cerr << "Error: This program must be run as Administrator!" << std::endl;
        std::cerr << "Please right-click and select 'Run as administrator'" << std::endl;
        return 1;
    }

        std::cout << "Creating TUN device..." << std::endl;
        if (!tun.create()) {
            std::cerr << "Failed to create TUN device" << std::endl;
            return 1;
        }

        std::cout << "Configuring TUN device..." << std::endl;
        if (!tun.configure("10.8.0.1", "255.255.255.0")) {
            std::cerr << "Failed to configure TUN device" << std::endl;
            return 1;
        }

        std::cout << "Bringing up TUN device..." << std::endl;
        if (!tun.bringUp()) {
            std::cerr << "Failed to bring up TUN device" << std::endl;
            return 1;
        }

        std::cout << "TUN device setup complete!" << std::endl;
        std::cout << "Press Enter to exit..." << std::endl;
        std::cin.get();

  // Add verification step
            if (!tun.verifyTunDevice()) {
                std::cerr << "TUN device verification failed" << std::endl;
                return 1;
            }

            std::cout << "TUN device setup complete!" << std::endl;
            std::cout << "Press Enter to exit..." << std::endl;
            std::cin.get();

            return 0;
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }
    }
    