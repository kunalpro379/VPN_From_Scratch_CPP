#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <iomanip>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

class VPNRouting
{
private:
    std::string vpnInterface;
    std::string vpnSubnet;
    std::string vpnNetmask;
    std::string vpnLocalIP;
    std::string vpnGatewayIP;
    DWORD vpnInterfaceIndex;
    IN_ADDR IPAddr;

    void printDetailedError(DWORD errorCode)
    {
        std::cerr << "Detailed Error Information:" << std::endl;
        std::cerr << "Error Code: " << errorCode << std::endl;

        // Translate Windows error codes
        LPVOID lpMsgBuf;
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
                FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            errorCode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR)&lpMsgBuf,
            0,
            NULL);

        std::cerr << "Error Message: " << (char *)lpMsgBuf << std::endl;
        LocalFree(lpMsgBuf);
    }

    bool getInterfaceIndex()
    {
        ULONG ulOutBufLen = 0;
        std::unique_ptr<IP_ADAPTER_INFO> pAdapterInfo;

        // First call to get the buffer size
        if (GetAdaptersInfo(NULL, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
        {
            pAdapterInfo.reset(reinterpret_cast<PIP_ADAPTER_INFO>(new char[ulOutBufLen]));
        }

        if (GetAdaptersInfo(pAdapterInfo.get(), &ulOutBufLen) == NO_ERROR)
        {
            PIP_ADAPTER_INFO pAdapter = pAdapterInfo.get();
            while (pAdapter)
            {
                std::string desc(pAdapter->Description);
                if (desc.find("TAP-Windows") != std::string::npos)
                {
                    vpnInterfaceIndex = pAdapter->Index;
                    std::cout << "Found TAP interface: " << pAdapter->Description << std::endl;
                    std::cout << "Interface index: " << vpnInterfaceIndex << std::endl;
                    std::cout << "Current IP: " << pAdapter->IpAddressList.IpAddress.String << std::endl;
                    return true;
                }
                pAdapter = pAdapter->Next;
            }
        }

        std::cerr << "TAP interface not found" << std::endl;
        return false;
    }

    bool configureInterface()
    {
        std::cout << "Configuring interface: " << vpnInterface << std::endl;

        // Disable and enable interface
        std::string reset_cmd = "netsh interface set interface \"" + vpnInterface + "\" disabled";
        std::cout << "Disabling interface..." << std::endl;
        system(reset_cmd.c_str());
        Sleep(2000);

        reset_cmd = "netsh interface set interface \"" + vpnInterface + "\" enabled";
        std::cout << "Enabling interface..." << std::endl;
        system(reset_cmd.c_str());
        Sleep(2000);

        // Set static IP address
        std::string ip_cmd = "netsh interface ip set address \"" + vpnInterface +
                             "\" static " + vpnLocalIP + " " + vpnNetmask + " " + vpnGatewayIP;
        std::cout << "Setting IP address command: " << ip_cmd << std::endl;
        int result = system(ip_cmd.c_str());
        if (result != 0)
        {
            std::cerr << "Failed to set IP address" << std::endl;
            return false;
        }
        Sleep(2000);

        return true;
    }

public:
    VPNRouting(const std::string &interfaceName,
               const std::string &subnet,
               const std::string &netmask,
               const std::string &localIP = "10.8.0.1",
               const std::string &gatewayIP = "10.8.0.2")
        : vpnInterface(interfaceName),
          vpnSubnet(subnet),
          vpnNetmask(netmask),
          vpnLocalIP(localIP),
          vpnGatewayIP(gatewayIP)
    {
    }

    bool addVPNRoute()
    {
        if (!getInterfaceIndex())
        {
            std::cerr << "Failed to get interface index" << std::endl;
            return false;
        }

        if (!configureInterface())
        {
            std::cerr << "Failed to configure interface IP" << std::endl;
            return false;
        }

        // Wait for interface to be ready
        Sleep(2000);

        // Check if the route exists before attempting to delete
        std::string check_cmd = "route print 10.8.0.0";
        if (system(check_cmd.c_str()) == 0)
        {
            // Route exists, attempt to delete it
            std::string delete_cmd = "route delete 10.8.0.0";
            std::cout << "Deleting existing routes: " << delete_cmd << std::endl;
            if (system(delete_cmd.c_str()) != 0)
            {
                std::cerr << "Failed to delete existing route. It may not exist." << std::endl;
            }
            Sleep(1000);
        }
        else
        {
            std::cout << "No existing route found for 10.8.0.0." << std::endl;
        }

        // Add both persistent and immediate routes
        std::string add_persistent = "route -p add 10.8.0.0 mask 255.255.255.0 10.8.0.2 metric 1 if " + std::to_string(vpnInterfaceIndex);
        std::cout << "Adding persistent route: " << add_persistent << std::endl;
        if (system(add_persistent.c_str()) != 0)
        {
            std::cerr << "Failed to add persistent route. It may already exist." << std::endl;
        }

        std::string add_immediate = "route add 10.8.0.0 mask 255.255.255.0 10.8.0.2 metric 1 if " + std::to_string(vpnInterfaceIndex);
        std::cout << "Adding immediate route: " << add_immediate << std::endl;
        if (system(add_immediate.c_str()) != 0)
        {
            std::cerr << "Failed to add immediate route. It may already exist." << std::endl;
        }

        // Verify the routes
        std::cout << "\nVerifying routes..." << std::endl;
        std::string verify_cmd = "route print 10.8.0.0";
        system(verify_cmd.c_str());

        return true;
    }

    bool removeVPNRoute()
    {
        std::cout << "Removing VPN routes..." << std::endl;

        // Check if the route exists before attempting to delete
        std::string check_cmd = "route print 10.8.0.0";
        if (system(check_cmd.c_str()) == 0)
        {
            std::string delete_persistent = "route delete 10.8.0.0 -p";
            std::string delete_immediate = "route delete 10.8.0.0";

            std::cout << "Removing persistent route: " << delete_persistent << std::endl;
            system(delete_persistent.c_str());
            Sleep(1000);

            std::cout << "Removing immediate route: " << delete_immediate << std::endl;
            int result = system(delete_immediate.c_str());

            if (result == 0)
            {
                std::cout << "Routes removed successfully" << std::endl;
                return true;
            }
            else
            {
                std::cerr << "Failed to remove routes. Error code: " << result << std::endl;
                return false;
            }
        }
        else
        {
            std::cout << "No routes to remove." << std::endl;
            return true; // No routes to remove, consider it successful
        }
    }

    void displayRoutes()
    {
        std::cout << "\nCurrent Routing Table:" << std::endl;
        std::cout << "Destination     Netmask         Gateway         Interface       Metric" << std::endl;
        std::cout << "-----------     -------         -------         ---------       ------" << std::endl;

        PMIB_IPFORWARDTABLE pIpForwardTable = NULL;
        DWORD dwSize = 0;
        char szDestIp[128];
        char szMaskIp[128];
        char szGatewayIp[128];

        // Get the size of the table
        GetIpForwardTable(NULL, &dwSize, TRUE);

        // Allocate memory for the table
        pIpForwardTable = (PMIB_IPFORWARDTABLE)malloc(dwSize);
        if (pIpForwardTable == NULL)
        {
            std::cerr << "Memory allocation failed for IP Forward Table" << std::endl;
            return;
        }

        if (GetIpForwardTable(pIpForwardTable, &dwSize, TRUE) == NO_ERROR)
        {
            for (DWORD i = 0; i < pIpForwardTable->dwNumEntries; i++)
            {
                IPAddr.S_un.S_addr = (u_long)pIpForwardTable->table[i].dwForwardDest;
                strcpy_s(szDestIp, sizeof(szDestIp), inet_ntoa(IPAddr));

                IPAddr.S_un.S_addr = (u_long)pIpForwardTable->table[i].dwForwardMask;
                strcpy_s(szMaskIp, sizeof(szMaskIp), inet_ntoa(IPAddr));

                IPAddr.S_un.S_addr = (u_long)pIpForwardTable->table[i].dwForwardNextHop;
                strcpy_s(szGatewayIp, sizeof(szGatewayIp), inet_ntoa(IPAddr));

                printf("%-15s %-15s %-15s %-15d %-d\n",
                       szDestIp,
                       szMaskIp,
                       szGatewayIp,
                       pIpForwardTable->table[i].dwForwardIfIndex,
                       pIpForwardTable->table[i].dwForwardMetric1);
            }
        }
        free(pIpForwardTable);
    }
};

int main()
{
    // Check for administrator privileges
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;

    if (AllocateAndInitializeSid(&NtAuthority, 2,
                                 SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS,
                                 0, 0, 0, 0, 0, 0,
                                 &AdministratorsGroup))
    {
        CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin);
        FreeSid(AdministratorsGroup);
    }

    if (!isAdmin)
    {
        std::cerr << "Error: This program must be run as Administrator!" << std::endl;
        std::cerr << "Please right-click and select 'Run as administrator'" << std::endl;
        return 1;
    }

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        std::cerr << "WSAStartup failed" << std::endl;
        return 1;
    }

    try
    {
        // Create VPN routing instance with the exact TAP interface name
        VPNRouting vpnRouting(
            "OpenVPN TAP-Windows6", // Interface name
            "10.8.0.0",             // Subnet
            "255.255.255.0",        // Netmask
            "10.8.0.1",             // Local IP (optional)
            "10.8.0.2"              // Gateway IP (optional)
        );
        // Display current routing table
        std::cout << "Displaying initial routing table..." << std::endl;
        vpnRouting.displayRoutes();

        // Add VPN route
        std::cout << "\nAdding VPN route..." << std::endl;
        if (!vpnRouting.addVPNRoute())
        {
            std::cerr << "Failed to add VPN route" << std::endl;
            WSACleanup();
            return 1;
        }

        // Display updated routing table
        std::cout << "\nDisplaying updated routing table..." << std::endl;
        vpnRouting.displayRoutes();

        std::cout << "\nPress Enter to remove the VPN route and exit..." << std::endl;
        std::cin.get();

        // Remove VPN route
        vpnRouting.removeVPNRoute();

        // Display final routing table
        std::cout << "\nDisplaying final routing table..." << std::endl;
        vpnRouting.displayRoutes();
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        WSACleanup();
        return 1;
    }

    WSACleanup();
    return 0;
}