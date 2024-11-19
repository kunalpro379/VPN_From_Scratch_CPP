#include <windows.h>
#include <iostream>
#include <string>
#include <winioctl.h>
#include <vector>
#include <iomanip> // For hex printing
#include <cstring> // For memset
#include <cstdint> // For uint16_t, etc.

#pragma comment(lib, "ws2_32.lib")

#define TAP_DEVICE_GUID "{9848B1C0-704B-42D1-81AA-78947DBF323D}" // Replace with your TAP device GUID
#define BUFFER_SIZE 1500                                         // MTU size for buffer
#define TAP_WIN_IOCTL_SET_MEDIA_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)

struct IPHeader
{
     uint8_t versionAndHeaderLength;
     uint8_t tos;
     uint16_t totalLength;
     uint16_t id;
     uint16_t flagsAndOffset;
     uint8_t ttl;
     uint8_t protocol;
     uint16_t checksum;
     uint32_t sourceIP;
     uint32_t destIP;
};

// Convert IP address from integer to human-readable string
std::string ipToString(uint32_t ip)
{
     uint8_t bytes[4];
     bytes[0] = ip & 0xFF;
     bytes[1] = (ip >> 8) & 0xFF;
     bytes[2] = (ip >> 16) & 0xFF;
     bytes[3] = (ip >> 24) & 0xFF;
     return std::to_string(bytes[0]) + "." + std::to_string(bytes[1]) + "." + std::to_string(bytes[2]) + "." + std::to_string(bytes[3]);
}

// Function to open the TAP device
HANDLE openTapDevice(const std::string &guid)
{
     std::string devicePath = "\\\\.\\Global\\" + guid + ".tap";
     HANDLE tapHandle = CreateFileA(
         devicePath.c_str(),
         GENERIC_READ | GENERIC_WRITE,
         0,
         nullptr,
         OPEN_EXISTING,
         FILE_ATTRIBUTE_SYSTEM,
         nullptr);

     if (tapHandle == INVALID_HANDLE_VALUE)
     {
          std::cerr << "Failed to open TAP device. Error: " << GetLastError() << std::endl;
          return nullptr;
     }

     std::cout << "Opened TAP device successfully." << std::endl;
     return tapHandle;
}

// Function to configure the TAP device (e.g., set it to 'connected' state)
void configureTapDevice(HANDLE tapHandle)
{
     DWORD len;
     ULONG status = TRUE;

     if (!DeviceIoControl(
             tapHandle,
             TAP_WIN_IOCTL_SET_MEDIA_STATUS,
             &status,
             sizeof(status),
             nullptr,
             0,
             &len,
             nullptr))
     {
          DWORD error = GetLastError();
          char errorMsg[256];
          FormatMessageA(
              FORMAT_MESSAGE_FROM_SYSTEM,
              NULL,
              error,
              MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
              errorMsg,
              sizeof(errorMsg),
              NULL);
          std::cerr << "Configuration failed. Error: " << error
                    << " - " << errorMsg << std::endl;
     }
}

// Function to extract and print IP header information
void printIPPacket(char *buffer, DWORD bytesRead)
{
     if (bytesRead < sizeof(IPHeader))
     {
          std::cerr << "Packet is too small to contain an IP header." << std::endl;
          return;
     }

     IPHeader *ipHeader = (IPHeader *)buffer;
     uint8_t version = ipHeader->versionAndHeaderLength >> 4;
     uint8_t headerLength = (ipHeader->versionAndHeaderLength & 0x0F) * 4;

     std::cout << "IP Packet Details:" << std::endl;
     std::cout << "Version: " << (int)version << std::endl;
     std::cout << "Header Length: " << (int)headerLength << " bytes" << std::endl;
     std::cout << "Total Length: " << ntohs(ipHeader->totalLength) << std::endl;
     std::cout << "TTL: " << (int)ipHeader->ttl << std::endl;
     std::cout << "Protocol: " << (int)ipHeader->protocol << std::endl;
     std::cout << "Source IP: " << ipToString(ntohl(ipHeader->sourceIP)) << std::endl;
     std::cout << "Destination IP: " << ipToString(ntohl(ipHeader->destIP)) << std::endl;

     // Print payload (if exists)
     if (bytesRead > headerLength)
     {
          std::cout << "Payload (first 64 bytes):" << std::endl;
          for (DWORD i = headerLength; i < std::min<DWORD>(bytesRead, headerLength + 64); i++)
          {
               printf("%02X ", (unsigned char)buffer[i]);
               if ((i - headerLength + 1) % 16 == 0)
                    std::cout << std::endl;
          }
          std::cout << std::endl;
     }
}

// Function to read packets from the TAP device
void interceptAndModifyPackets(HANDLE tapHandle)
{
     char buffer[BUFFER_SIZE];
     DWORD bytesRead;

     while (true)
     {
          std::cout << "Waiting for packets..." << std::endl;
          if (ReadFile(tapHandle, buffer, BUFFER_SIZE, &bytesRead, nullptr))
          {
               std::cout << "Intercepted " << bytesRead << " bytes from TAP device." << std::endl;

               // Print the packet details as IP header
               printIPPacket(buffer, bytesRead);
          }
          else
          {
               DWORD error = GetLastError();
               if (error == ERROR_OPERATION_ABORTED)
               {
                    std::cerr << "Read operation aborted." << std::endl;
                    break;
               }
               std::cerr << "Failed to read from TAP device. Error: " << error << std::endl;
               break;
          }
     }
}

int main()
{
     // Open the TAP device with the provided GUID
     HANDLE tapHandle = openTapDevice(TAP_DEVICE_GUID);
     if (tapHandle != INVALID_HANDLE_VALUE)
     {
          // Configure the TAP device if it is successfully opened
          configureTapDevice(tapHandle);

          // Start intercepting and processing packets
          interceptAndModifyPackets(tapHandle);

          // Close the TAP device when done
          CloseHandle(tapHandle);
     }

     return 0;
}
