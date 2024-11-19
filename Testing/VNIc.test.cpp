#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winioctl.h>

#pragma comment(lib, "ws2_32.lib")

#define TAP_WIN_IOCTL_SET_MEDIA_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TAP_WIN_IOCTL_CONFIG_TUN CTL_CODE(FILE_DEVICE_UNKNOWN, 10, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Helper function to get error message
std::string GetLastErrorAsString(DWORD errorMessageID)
{
     LPSTR messageBuffer = nullptr;
     FormatMessageA(
         FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
         NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
         (LPSTR)&messageBuffer, 0, NULL);

     std::string message(messageBuffer);
     LocalFree(messageBuffer);
     return message;
}

ULONG ipStringToNetworkLong(const std::string &ipStr)
{
     // Use inet_addr for Windows IP conversion
     ULONG addr = inet_addr(ipStr.c_str());
     if (addr == INADDR_NONE)
     {
          std::cerr << "Invalid IP address: " << ipStr << std::endl;
          return 0;
     }
     return addr; // This returns in network byte order
}

HANDLE openTapDevice(const std::string &guid)
{
     std::string devicePath = "\\\\.\\Global\\" + guid + ".tap"; // Format the device path with the GUID
     HANDLE tapHandle = CreateFileA(
         devicePath.c_str(),
         GENERIC_READ | GENERIC_WRITE,
         0, nullptr, OPEN_EXISTING,
         FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
         nullptr);

     if (tapHandle == INVALID_HANDLE_VALUE)
     {
          DWORD error = GetLastError();
          std::cerr << "Failed to open TAP device. Error code: " << error << std::endl;
          return nullptr;
     }

     std::cout << "TAP device opened successfully." << std::endl;
     return tapHandle;
}

bool configureTapDevice(HANDLE tapHandle)
{
     DWORD len;
     ULONG status = TRUE;

     if (!DeviceIoControl(
             tapHandle,
             TAP_WIN_IOCTL_SET_MEDIA_STATUS,
             &status, sizeof(status),
             nullptr, 0,
             &len,
             nullptr))
     {
          DWORD error = GetLastError();
          char *errorText = nullptr;
          FormatMessageA(
              FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
              nullptr, error, 0, (LPSTR)&errorText, 0, nullptr);
          std::cerr << "Failed to configure TAP device. Error code: " << error << " - " << errorText << std::endl;
          LocalFree(errorText);
          return false;
     }

     std::cout << "TAP device configured successfully." << std::endl;
     return true;
}

#pragma pack(push, 1)
struct TunConfig
{
     ULONG ip;
     ULONG netmask;
     ULONG gateway; // Add gateway field
     ULONG metric;  // Optional metric field
};
#pragma pack(pop)

bool setTunConfiguration(HANDLE tapHandle, const std::string &ipStr, const std::string &netmaskStr, const std::string &gatewayStr)
{
     struct
     {
          ULONG ip;
          ULONG netmask;
          ULONG gateway;
          ULONG metric = 0;
     } tunConfig = {0};

     tunConfig.ip = htonl(inet_addr(ipStr.c_str()));           // Use htonl for correct byte order
     tunConfig.netmask = htonl(inet_addr(netmaskStr.c_str())); // Use htonl for correct byte order
     tunConfig.gateway = htonl(inet_addr(gatewayStr.c_str())); // Use htonl for correct byte order

     std::cout << "IP Address: " << ipStr << std::endl;
     std::cout << "Netmask: " << netmaskStr << std::endl;
     std::cout << "Gateway: " << gatewayStr << std::endl;
     std::cout << "Raw IP: 0x" << std::hex << tunConfig.ip << std::endl;
     std::cout << "Raw Netmask: 0x" << tunConfig.netmask << std::endl;
     std::cout << "Raw Gateway: 0x" << tunConfig.gateway << std::dec << std::endl;

     DWORD len;
     char buffer[128] = {0};
     BOOL result = DeviceIoControl(
         tapHandle,
         TAP_WIN_IOCTL_CONFIG_TUN,
         &tunConfig, sizeof(tunConfig),
         buffer, sizeof(buffer),
         &len,
         nullptr);

     if (!result)
     {
          DWORD error = GetLastError();
          std::cerr << "Configuration Failed. Error: " << error
                    << " (" << GetLastErrorAsString(error) << ")" << std::endl;
          return false;
     }

     return true;
}

int main()
{
     // Initialize Windows Sockets API
     WSADATA wsaData;
     if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
     {
          std::cerr << "WSAStartup failed!" << std::endl;
          return 1;
     }

     // Specific TAP device GUID - adjust as needed
     const std::string TAP_DEVICE_GUID = "{9848B1C0-704B-42D1-81AA-78947DBF323D}";

     std::cout << "Creating Virtual Network Interface using TAP-Windows..." << std::endl;

     // Open the TAP device
     HANDLE tapHandle = openTapDevice(TAP_DEVICE_GUID);
     if (tapHandle == nullptr)
     {
          WSACleanup(); // Clean up before returning
          return 1;
     }

     // Configure TAP device
     if (!configureTapDevice(tapHandle))
     {
          CloseHandle(tapHandle); // Close the TAP device handle if configuration failed
          WSACleanup();
          return 1;
     }

     // Example IP configuration (replace with actual values)
     std::string ip = "192.168.210.227";
     std::string netmask = "255.255.255.0";
     std::string gateway = "192.168.210.1"; // Example gateway, update as needed

     if (!setTunConfiguration(tapHandle, ip, netmask, gateway))
     {
          CloseHandle(tapHandle); // Close handle if TUN configuration fails
          WSACleanup();
          return 1;
     }

     std::cout << "Virtual Network Interface successfully created." << std::endl;
     std::cout << "Press any key to exit..." << std::endl;
     std::cin.get();

     // Clean up and close handles
     CloseHandle(tapHandle);
     WSACleanup();
     return 0;
}
