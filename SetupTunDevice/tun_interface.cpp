#include "tun_interface.h"

// Constructor
TunInterface::TunInterface() : 
    tunHandle(INVALID_HANDLE_VALUE), 
    running(false), 
    originalRoutes(nullptr) {
}

// Destructor
TunInterface::~TunInterface() {
    stop();
}

bool TunInterface::findTapDevice() {
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
                        std::cout << "Found TAP device at: " << devicePath << std::endl;
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
    std::cerr << "No TAP device found" << std::endl;
    return false;
}

bool TunInterface::backupRoutingTable() {
    DWORD size = 0;
    if (GetIpForwardTable(NULL, &size, FALSE) != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "Failed to get routing table size" << std::endl;
        return false;
    }

    originalRoutes = (PMIB_IPFORWARDTABLE)malloc(size);
    if (GetIpForwardTable(originalRoutes, &size, FALSE) != NO_ERROR) {
        std::cerr << "Failed to backup routing table" << std::endl;
        free(originalRoutes);
        originalRoutes = nullptr;
        return false;
    }
    return true;
}

bool TunInterface::configureRoute() {
    // Get adapter info to find our TAP adapter
    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    ULONG ulOutBufLen = 0;
    DWORD dwRetVal;

    // Diagnostic: List all network adapters
    std::cout << "Discovering Network Adapters:" << std::endl;

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
        int adapterCount = 0;
        while (pAdapter) {
            std::cout << "Adapter " << ++adapterCount << ": " 
                      << pAdapter->Description 
                      << " (Type: " << (int)pAdapter->Type 
                      << ", Index: " << pAdapter->Index << ")" << std::endl;

            // Prefer the first TAP adapter
            if (tapAdapterIndex == 0 && 
                (strstr(pAdapter->Description, "TAP-Windows Adapter V9") != NULL ||
                 strstr(pAdapter->Description, "TAP") != NULL)) {
                tapAdapterIndex = pAdapter->Index;
                std::cout << "Found TAP Adapter: " << pAdapter->Description 
                          << " (Index: " << tapAdapterIndex << ")" << std::endl;
            }
            pAdapter = pAdapter->Next;
        }
    }

    // Validate TAP adapter
    if (tapAdapterIndex == 0) {
        std::cerr << "Error: No TAP adapter found" << std::endl;
        free(pAdapterInfo);
        return false;
    }

    // Retrieve current routing table for diagnostics
    PMIB_IPFORWARDTABLE pRouteTable = NULL;
    DWORD routeTableSize = 0;
    
    if (GetIpForwardTable(NULL, &routeTableSize, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        pRouteTable = (PMIB_IPFORWARDTABLE)malloc(routeTableSize);
        if (GetIpForwardTable(pRouteTable, &routeTableSize, FALSE) == NO_ERROR) {
            std::cout << "\nCurrent Routing Table:" << std::endl;
            for (DWORD i = 0; i < pRouteTable->dwNumEntries; i++) {
                char destStr[16], maskStr[16], nextHopStr[16];
                inet_ntop(AF_INET, &pRouteTable->table[i].dwForwardDest, destStr, sizeof(destStr));
                inet_ntop(AF_INET, &pRouteTable->table[i].dwForwardMask, maskStr, sizeof(maskStr));
                inet_ntop(AF_INET, &pRouteTable->table[i].dwForwardNextHop, nextHopStr, sizeof(nextHopStr));
                
                std::cout << "Route " << i+1 << ": "
                          << "Dest: " << destStr 
                          << ", Mask: " << maskStr 
                          << ", NextHop: " << nextHopStr 
                          << ", Interface: " << pRouteTable->table[i].dwForwardIfIndex 
                          << std::endl;
            }
        }
    }

    // Prepare route configurations for internet traffic
    MIB_IPFORWARDROW routes[] = {
        // Specific route for a test network
        {
            .dwForwardDest = inet_addr("10.0.0.0"),     // Test network
            .dwForwardMask = inet_addr("255.0.0.0"),    // Large network mask
            .dwForwardNextHop = inet_addr("0.0.0.0"),   // Direct route
            .dwForwardIfIndex = tapAdapterIndex,        // Our TAP interface
            .dwForwardType = 3,  // Direct route
            .dwForwardProto = 3, // Manually configured
            .dwForwardAge = 0,   // Permanent route
            .dwForwardMetric1 = 10
        }
    };

    // Add routes
    for (auto& route : routes) {
        char destStr[16], maskStr[16], nextHopStr[16];
        inet_ntop(AF_INET, &route.dwForwardDest, destStr, sizeof(destStr));
        inet_ntop(AF_INET, &route.dwForwardMask, maskStr, sizeof(maskStr));
        inet_ntop(AF_INET, &route.dwForwardNextHop, nextHopStr, sizeof(nextHopStr));

        std::cout << "\nAttempting to configure route:" << std::endl;
        std::cout << "Destination: " << destStr 
                  << ", Mask: " << maskStr 
                  << ", NextHop: " << nextHopStr 
                  << ", Interface: " << route.dwForwardIfIndex << std::endl;

        // Attempt to delete existing route first
        DWORD deleteResult = DeleteIpForwardEntry(&route);
        if (deleteResult != NO_ERROR && deleteResult != ERROR_NOT_FOUND) {
            std::cerr << "Warning: Failed to delete existing route. Error: " << deleteResult << std::endl;
        }

        // Add new route
        DWORD result = CreateIpForwardEntry(&route);
        if (result != NO_ERROR) {
            std::cerr << "Failed to add route. Error: " << result << std::endl;
            std::cerr << "Possible reasons:" << std::endl;
            switch(result) {
                case ERROR_ACCESS_DENIED:
                    std::cerr << "- Insufficient permissions. Run as administrator." << std::endl;
                    break;
                case ERROR_INVALID_PARAMETER:
                    std::cerr << "- Invalid route parameters." << std::endl;
                    break;
                case ERROR_NOT_SUPPORTED:
                    std::cerr << "- Route configuration not supported." << std::endl;
                    break;
                case 160: // Specific error we're seeing
                    std::cerr << "- Potential network configuration conflict or routing table lock." << std::endl;
                    break;
                default:
                    std::cerr << "- Unknown error. Check system configuration." << std::endl;
            }
        } else {
            std::cout << "Successfully added route: " 
                      << destStr << "/" << maskStr 
                      << std::endl;
        }
    }

    // Cleanup
    if (pRouteTable) free(pRouteTable);
    free(pAdapterInfo);
    
    return true;
}

void TunInterface::restoreRoutingTable() {
    if (originalRoutes) {
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

    std::cout << "Packet processing thread started. Waiting for IP packets..." << std::endl;

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

        // Check if this is an IP packet (IPv4)
        if (bytesRead > 0 && buffer[0] >> 4 == 4) {
            // Print packet info
            std::cout << "\n=== Intercepted IP Packet ===" << std::endl;
            std::cout << "Size: " << bytesRead << " bytes" << std::endl;

            // Minimum IP header size is 20 bytes
            if (bytesRead >= 20) {
                uint8_t ihl = buffer[0] & 0xF;
                uint8_t protocol = buffer[9];
                uint32_t srcIP = *(uint32_t*)(buffer.data() + 12);
                uint32_t dstIP = *(uint32_t*)(buffer.data() + 16);

                // Convert IPs to string
                in_addr src, dst;
                src.s_addr = srcIP;
                dst.s_addr = dstIP;

                std::cout << "IP Header:" << std::endl;
                std::cout << "  Header Length: " << (ihl * 4) << " bytes" << std::endl;
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

                // Optional: Hex dump of packet payload
                std::cout << "  Payload Hex (first 32 bytes):" << std::endl;
                std::cout << "  ";
                for (int i = 0; i < std::min(32, (int)bytesRead); ++i) {
                    printf("%02X ", buffer[i]);
                    if ((i + 1) % 16 == 0) std::cout << std::endl << "  ";
                }
                std::cout << std::endl;
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

bool TunInterface::start() {
    std::cout << "Starting TUN interface initialization..." << std::endl;
    
    // Find TAP device
    if (!findTapDevice()) {
        std::cerr << "No TAP device found. Error code: " << GetLastError() << std::endl;
        return false;
    }

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

    // Backup current routing table
    if (!backupRoutingTable()) {
        std::cerr << "Failed to backup routing table. Error code: " << GetLastError() << std::endl;
        CloseHandle(tunHandle);
        return false;
    }

    // Modify routing table
    if (!configureRoute()) {
        std::cerr << "Failed to modify routing table. Error code: " << GetLastError() << std::endl;
        restoreRoutingTable();
        CloseHandle(tunHandle);
        return false;
    }

    running = true;
    routingThread = std::thread(&TunInterface::processPackets, this);

    std::cout << "TUN interface started successfully" << std::endl;
    std::cout << "All traffic is now being routed through the TUN interface" << std::endl;
    return true;
}

void TunInterface::stop() {
    running = false;

    // Wait for routing thread to finish
    if (routingThread.joinable()) {
        routingThread.join();
    }

    // Close handle if open
    if (tunHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(tunHandle);
        tunHandle = INVALID_HANDLE_VALUE;
    }

    // Restore routing table if needed
    restoreRoutingTable();
}