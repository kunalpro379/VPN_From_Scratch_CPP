#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <winioctl.h>

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
bool modifyRoutingTable() {
    // Get adapter info to find our IP
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

    std::cout << "Searching for TAP adapter in adapter list..." << std::endl;
    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
        IP_ADAPTER_INFO* pAdapter = pAdapterInfo;
        while (pAdapter) {
            std::cout << "Checking adapter: " << pAdapter->Description 
                     << " (Index: " << pAdapter->Index 
                     << ", Type: " << pAdapter->Type 
                     << ", IP: " << pAdapter->IpAddressList.IpAddress.String 
                     << ")" << std::endl;

            // Look for TAP adapter by description and ensure it has a valid IP
            if (strstr(pAdapter->Description, "TAP-Windows Adapter V9") != NULL &&
                strcmp(pAdapter->IpAddressList.IpAddress.String, "0.0.0.0") != 0) {
                std::cout << "Found matching TAP adapter!" << std::endl;
                
                MIB_IPFORWARDROW route;
                memset(&route, 0, sizeof(route));
                route.dwForwardDest = 0;           // 0.0.0.0 (default route)
                route.dwForwardMask = 0;           // 0.0.0.0 (match all)
                route.dwForwardPolicy = 0;
                route.dwForwardNextHop = inet_addr(pAdapter->IpAddressList.IpAddress.String);
                route.dwForwardIfIndex = pAdapter->Index;  // Use the actual adapter index
                route.dwForwardType = MIB_IPROUTE_TYPE_DIRECT;
                route.dwForwardProto = MIB_IPPROTO_NETMGMT;
                route.dwForwardAge = 0;
                route.dwForwardMetric1 = 1;
                route.dwForwardMetric2 = -1;
                route.dwForwardMetric3 = -1;
                route.dwForwardMetric4 = -1;
                route.dwForwardMetric5 = -1;

                std::cout << "Adding route with next hop IP: " << pAdapter->IpAddressList.IpAddress.String 
                         << " and interface index: " << pAdapter->Index << std::endl;

                // Add the new route
                DWORD result = CreateIpForwardEntry(&route);
                if (result != NO_ERROR) {
                    std::cerr << "Failed to add route. Error code: " << result << std::endl;
                    if (result == ERROR_INVALID_PARAMETER) {
                        std::cerr << "Invalid parameter in route configuration" << std::endl;
                    }
                    free(pAdapterInfo);
                    return false;
                }
                
                free(pAdapterInfo);
                return true;
            }
            pAdapter = pAdapter->Next;
        }
    } else {
        std::cerr << "Failed to get adapters info. Error: " << dwRetVal << std::endl;
    }

    if (pAdapterInfo) {
        free(pAdapterInfo);
    }

    std::cerr << "TAP adapter not found in adapter list" << std::endl;
    return false;
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

void TunInterface::processPackets() {
    std::vector<uint8_t> buffer(65536);
    DWORD bytesRead;
    OVERLAPPED overlapped = {0};
    overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    std::cout << "Packet processing thread started. Waiting for packets..." << std::endl;

    while (running) {
        // Reset the event
        ResetEvent(overlapped.hEvent);

        // Read packets asynchronously
        if (ReadFile(tunHandle, buffer.data(), buffer.size(), NULL, &overlapped)) {
            // Synchronous read completed immediately
            bytesRead = overlapped.InternalHigh;
        } else {
            // Asynchronous read in progress
            if (GetLastError() == ERROR_IO_PENDING) {
                // Wait for the read to complete
                if (WaitForSingleObject(overlapped.hEvent, 1000) == WAIT_OBJECT_0) {
                    // Read completed successfully
                    bytesRead = overlapped.InternalHigh;
                } else {
                    // Timeout or error
                    continue;
                }
            } else {
                // Error occurred
                std::cerr << "ReadFile failed. Error: " << GetLastError() << std::endl;
                break;
            }
        }

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

    // Clean up
    CloseHandle(overlapped.hEvent);
    std::cout << "Packet processing thread stopped." << std::endl;
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
        if (!modifyRoutingTable()) {
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

int main() {
    std::cout << "Starting TUN Interface..." << std::endl;
    std::cout << "WARNING: This will redirect all network traffic!" << std::endl;
    std::cout << "WARNING: Only use this for educational purposes!" << std::endl;
    
    TunInterface tun;
    if (!tun.start()) {
        std::cerr << "Failed to start TUN interface" << std::endl;
        return 1;
    }

    std::cout << "Press Enter to stop..." << std::endl;
    std::cin.get();

    return 0;
}
