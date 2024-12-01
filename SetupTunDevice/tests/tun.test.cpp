#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <winioctl.h>

#include <iostream>
#include <string>
#include <vector>
#include <thread>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// TAP-Windows device GUID
#define TAP_WINDOWS_GUID "tap0901"

// TAP IOCTLs
#define TAP_CONTROL_CODE(request,method) CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
#define TAP_IOCTL_GET_MAC               TAP_CONTROL_CODE(1, METHOD_BUFFERED)
#define TAP_IOCTL_GET_VERSION           TAP_CONTROL_CODE(2, METHOD_BUFFERED)
#define TAP_IOCTL_SET_MEDIA_STATUS      TAP_CONTROL_CODE(6, METHOD_BUFFERED)

class TunInterface {
private:
    HANDLE tunHandle;
    std::string devicePath;
    bool running;
    std::thread routingThread;

    // Original routing table backup
    MIB_IPFORWARDTABLE* originalRoutes;
    
    bool findTapDevice() {
        char windowsDirectory[MAX_PATH];
        GetWindowsDirectory(windowsDirectory, MAX_PATH);
        std::string networkPath = std::string(windowsDirectory) + "\\system32\\drivers\\etc\\network";
        
        // Open network adapters key
        HKEY adaptersKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}",
            0, KEY_READ, &adaptersKey) != ERROR_SUCCESS) {
            std::cerr << "Failed to open network adapters registry key" << std::endl;
            return false;
        }

        char valueName[256];
        DWORD valueNameSize;
        DWORD index = 0;

        // Enumerate all subkeys
        while (true) {
            valueNameSize = sizeof(valueName);
            if (RegEnumKeyEx(adaptersKey, index, valueName, &valueNameSize,
                NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
                break;
            }

            // Open the adapter's key
            HKEY adapterKey;
            std::string keyPath = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\" + std::string(valueName);
            if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_READ, &adapterKey) == ERROR_SUCCESS) {
                char componentId[256];
                DWORD dataSize = sizeof(componentId);
                
                // Check if this is a TAP adapter
                if (RegQueryValueEx(adapterKey, "ComponentId", NULL, NULL, (LPBYTE)componentId, &dataSize) == ERROR_SUCCESS) {
                    if (strncmp(componentId, "tap0901", strlen("tap0901")) == 0) {
                        char netCfgInstanceId[256];
                        dataSize = sizeof(netCfgInstanceId);
                        
                        if (RegQueryValueEx(adapterKey, "NetCfgInstanceId", NULL, NULL,
                            (LPBYTE)netCfgInstanceId, &dataSize) == ERROR_SUCCESS) {
                            devicePath = "\\\\.\\Global\\" + std::string(netCfgInstanceId) + ".tap";
                            RegCloseKey(adapterKey);
                            RegCloseKey(adaptersKey);
                            return true;
                        }
                    }
                }
                RegCloseKey(adapterKey);
            }
            index++;
        }

        RegCloseKey(adaptersKey);
        return false;
    }

    bool backupRoutingTable() {
        DWORD size = 0;
        if (GetIpForwardTable(NULL, &size, FALSE) != ERROR_INSUFFICIENT_BUFFER) {
            return false;
        }

        originalRoutes = (MIB_IPFORWARDTABLE*)malloc(size);
        if (GetIpForwardTable(originalRoutes, &size, FALSE) != NO_ERROR) {
            free(originalRoutes);
            return false;
        }
        return true;
    }

    bool configureRoute() {
        // Get adapter info to find our TAP adapter
        PIP_ADAPTER_INFO pAdapterInfo = NULL;
        ULONG ulOutBufLen = 0;
        DWORD dwRetVal;

        if (GetAdaptersInfo(NULL, &ulOutBufLen) != ERROR_BUFFER_OVERFLOW) {
            std::cerr << "Failed to get adapter info buffer size. Error: " << GetLastError() << std::endl;
            return false;
        }

        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            std::cerr << "Failed to allocate memory for adapter info" << std::endl;
            return false;
        }

        DWORD tapAdapterIndex = 0;
        if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
            IP_ADAPTER_INFO* pAdapter = pAdapterInfo;
            while (pAdapter) {
                // Look for TAP adapter
                if ((strstr(pAdapter->Description, "TAP-Windows Adapter V9") != NULL ||
                     strstr(pAdapter->Description, "TAP") != NULL)) {
                    tapAdapterIndex = pAdapter->Index;
                    break;
                }
                pAdapter = pAdapter->Next;
            }
        }

        // Validate TAP adapter
        if (tapAdapterIndex == 0) {
            std::cerr << "Error: TAP adapter not found" << std::endl;
            free(pAdapterInfo);
            return false;
        }

        // Prepare route configuration
        MIB_IPFORWARDROW route;
        ZeroMemory(&route, sizeof(route));

        // Explicitly set route parameters
        route.dwForwardDest = inet_addr("10.0.0.0");        // Destination network
        route.dwForwardMask = inet_addr("255.0.0.0");       // Subnet mask
        route.dwForwardNextHop = inet_addr("0.0.0.0");      // Direct route
        route.dwForwardIfIndex = tapAdapterIndex;           // TAP adapter index
        route.dwForwardType = 3;                            // Direct route
        route.dwForwardProto = 3;                           // Manually configured
        route.dwForwardAge = 0;                             // Permanent route
        route.dwForwardMetric1 = 10;                        // Metric

        // Detailed logging of route configuration
        std::cout << "Route Configuration Details:" << std::endl;
        std::cout << "  Destination: 10.0.0.0" << std::endl;
        std::cout << "  Mask: 255.0.0.0" << std::endl;
        std::cout << "  Next Hop: 0.0.0.0" << std::endl;
        std::cout << "  Interface Index: " << tapAdapterIndex << std::endl;

        // Attempt to delete existing route first (optional, but can help)
        DeleteIpForwardEntry(&route);

        // Attempt to add route
        DWORD result = CreateIpForwardEntry(&route);
        
        // Free adapter info before any potential return
        free(pAdapterInfo);

        if (result != NO_ERROR) {
            DWORD errorCode = GetLastError();
            char errorBuffer[256] = {0};
            
            FormatMessageA(
                FORMAT_MESSAGE_FROM_SYSTEM,
                NULL,
                errorCode,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                errorBuffer,
                sizeof(errorBuffer),
                NULL
            );

            std::cerr << "Route Addition Failure:" << std::endl;
            std::cerr << "  Error Code: " << errorCode << std::endl;
            std::cerr << "  System Error Message: " << (errorBuffer[0] ? errorBuffer : "Unknown Error") << std::endl;

            return false;
        }

        std::cout << "Route successfully added!" << std::endl;
        return true;
    }

    void restoreRoutingTable() {
        if (originalRoutes) {
            // Delete all current routes
            PMIB_IPFORWARDTABLE routes;
            DWORD size = 0;
            if (GetIpForwardTable(NULL, &size, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
                routes = (MIB_IPFORWARDTABLE*)malloc(size);
                if (GetIpForwardTable(routes, &size, FALSE) == NO_ERROR) {
                    for (DWORD i = 0; i < routes->dwNumEntries; i++) {
                        DeleteIpForwardEntry(&routes->table[i]);
                    }
                }
                free(routes);
            }

            // Restore original routes
            for (DWORD i = 0; i < originalRoutes->dwNumEntries; i++) {
                SetIpForwardEntry(&originalRoutes->table[i]);
            }

            free(originalRoutes);
            originalRoutes = nullptr;
        }
    }

    void processPackets() {
        std::vector<uint8_t> buffer(65536);
        DWORD bytesRead;

        while (running) {
            if (ReadFile(tunHandle, buffer.data(), buffer.size(), &bytesRead, NULL)) {
                if (bytesRead > 0) {
                    // Print packet info
                    std::cout << "\n=== Intercepted Packet ===" << std::endl;
                    std::cout << "Size: " << bytesRead << " bytes" << std::endl;

                    // Parse IP header
                    if (bytesRead >= 20) {  // Minimum IP header size
                        uint8_t version = (buffer[0] >> 4) & 0xF;
                        uint8_t ihl = buffer[0] & 0xF;
                        uint8_t protocol = buffer[9];
                        uint32_t srcIP = *(uint32_t*)(buffer.data() + 12);
                        uint32_t dstIP = *(uint32_t*)(buffer.data() + 16);

                        // Convert IPs to string
                        in_addr src, dst;
                        src.s_addr = srcIP;
                        dst.s_addr = dstIP;

                        std::cout << "IP Header:" << std::endl;
                        std::cout << "  Version: IPv" << (int)version << std::endl;
                        std::cout << "  Protocol: ";
                        switch(protocol) {
                            case IPPROTO_TCP: std::cout << "TCP"; break;
                            case IPPROTO_UDP: std::cout << "UDP"; break;
                            case IPPROTO_ICMP: std::cout << "ICMP"; break;
                            default: std::cout << "Unknown (" << (int)protocol << ")";
                        }
                        std::cout << std::endl;
                        std::cout << "  Source IP: " << inet_ntoa(src) << std::endl;
                        std::cout << "  Destination IP: " << inet_ntoa(dst) << std::endl;

                        // For TCP/UDP, show ports
                        if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
                            int headerLen = ihl * 4;
                            if (bytesRead >= (size_t)(headerLen + 4)) {
                                uint16_t srcPort = ntohs(*(uint16_t*)(buffer.data() + headerLen));
                                uint16_t dstPort = ntohs(*(uint16_t*)(buffer.data() + headerLen + 2));
                                std::cout << "  Source Port: " << srcPort << std::endl;
                                std::cout << "  Destination Port: " << dstPort << std::endl;
                            }
                        }
                    }

                    std::cout << "======================" << std::endl;

                    // Forward the packet (in a real VPN, you'd encrypt it here)
                    DWORD bytesWritten;
                    WriteFile(tunHandle, buffer.data(), bytesRead, &bytesWritten, NULL);
                }
            }
        }
    }

public:
    TunInterface() : tunHandle(INVALID_HANDLE_VALUE), running(false), originalRoutes(nullptr) {}

    ~TunInterface() {
        stop();
    }

    bool start() {
        std::cout << "Starting TUN interface initialization..." << std::endl;
        
        // Find TAP device
        if (!findTapDevice()) {
            std::cerr << "No TAP device found. Error code: " << GetLastError() << std::endl;
            return false;
        }
        std::cout << "Found TAP device at: " << devicePath << std::endl;

        // Open TAP device
        tunHandle = CreateFile(
            devicePath.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            0,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
            0);

        if (tunHandle == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            std::cerr << "Failed to open TAP device. Error code: " << error << std::endl;
            if (error == ERROR_ACCESS_DENIED) {
                std::cerr << "Access denied. Make sure you're running with administrator privileges." << std::endl;
            }
            return false;
        }
        std::cout << "Successfully opened TAP device" << std::endl;

        // Set TAP status to connected
        ULONG status = 1;
        DWORD len;
        if (!DeviceIoControl(tunHandle, TAP_IOCTL_SET_MEDIA_STATUS,
            &status, sizeof(status),
            &status, sizeof(status),
            &len, NULL)) {
            DWORD error = GetLastError();
            std::cerr << "Failed to set TAP status. Error code: " << error << std::endl;
            CloseHandle(tunHandle);
            return false;
        }
        std::cout << "TAP device media status set to connected" << std::endl;

        // Backup current routing table
        if (!backupRoutingTable()) {
            std::cerr << "Failed to backup routing table. Error code: " << GetLastError() << std::endl;
            CloseHandle(tunHandle);
            return false;
        }
        std::cout << "Successfully backed up routing table" << std::endl;

        // Modify routing table
        if (!configureRoute()) {
            std::cerr << "Failed to modify routing table. Error code: " << GetLastError() << std::endl;
            restoreRoutingTable();
            CloseHandle(tunHandle);
            return false;
        }
        std::cout << "Successfully modified routing table" << std::endl;

        running = true;
        routingThread = std::thread(&TunInterface::processPackets, this);

        std::cout << "TUN interface started successfully" << std::endl;
        std::cout << "All traffic is now being routed through the TUN interface" << std::endl;
        return true;
    }

    void stop() {
        running = false;
        if (routingThread.joinable()) {
            routingThread.join();
        }

        if (tunHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(tunHandle);
            tunHandle = INVALID_HANDLE_VALUE;
        }

        restoreRoutingTable();
    }
};

// int main() {
//     std::cout << "Starting TUN Interface..." << std::endl;
//     std::cout << "WARNING: This will redirect all network traffic!" << std::endl;
//     std::cout << "WARNING: Only use this for educational purposes!" << std::endl;
    
//     TunInterface tun;
//     if (!tun.start()) {
//         std::cerr << "Failed to start TUN interface" << std::endl;
//         return 1;
//     }

//     std::cout << "Press Enter to stop..." << std::endl;
//     std::cin.get();

//     return 0;
// }
