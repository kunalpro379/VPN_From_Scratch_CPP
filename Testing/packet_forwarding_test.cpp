#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <cstdint>
#include <winioctl.h>
#include <winerror.h>
#pragma comment(lib, "ws2_32.lib")
#include <algorithm> // Include for std::min

#define TAP_DEVICE_GUID "{9848B1C0-704B-42D1-81AA-78947DBF323D}" // Replace with your TAP device GUID
#define BUFFER_SIZE 1500
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 12345
#define TAP_WIN_IOCTL_SET_MEDIA_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)

struct IPHeader
{
     uint8_t versionAndHeaderLength;
     uint8_t typeOfService;
     uint16_t totalLength;
     uint16_t identification;
     uint16_t flagsAndFragmentOffset;
     uint8_t timeToLive;
     uint8_t protocol;
     uint16_t headerChecksum;
     uint32_t sourceIP;
     uint32_t destIP;
};

void debugPacket(const char *buffer, DWORD bytesRead)
{
     std::cout << "Packet hex dump (first 16 bytes): ";
     for (DWORD i = 0; i < std::min(bytesRead, (DWORD)16); i++)
     {
          printf("%02x ", (unsigned char)buffer[i]);
     }
     std::cout << std::endl;
}

std::string getLastErrorMessage()
{
     DWORD error = GetLastError();
     char message[256];
     FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, nullptr, error,
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                    message, sizeof(message), nullptr);
     return "Error " + std::to_string(error) + ": " + message;
}

HANDLE openTapDevice(const std::string &guid)
{
     std::string devicePath = "\\\\.\\Global\\" + guid + ".tap";
     HANDLE tapHandle = CreateFileA(devicePath.c_str(),
                                    GENERIC_READ | GENERIC_WRITE,
                                    0, nullptr, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
                                    nullptr);

     if (tapHandle == INVALID_HANDLE_VALUE)
     {
          std::cerr << "Failed to open TAP device: " << getLastErrorMessage() << std::endl;
          return nullptr;
     }

     std::cout << "TAP device opened successfully." << std::endl;
     return tapHandle;
}

bool configureTapDevice(HANDLE tapHandle)
{
     DWORD len;
     ULONG status = TRUE;

     if (!DeviceIoControl(tapHandle, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
                          &status, sizeof(status), nullptr, 0, &len, nullptr))
     {
          std::cerr << "Failed to configure TAP device: " << getLastErrorMessage() << std::endl;
          return false;
     }

     std::cout << "TAP device configured successfully." << std::endl;
     return true;
}

SOCKET initRawSocket()
{
     WSADATA wsaData;
     if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
     {
          std::cerr << "WSAStartup failed with error: " << WSAGetLastError() << std::endl;
          return INVALID_SOCKET;
     }

     SOCKET rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
     if (rawSocket == INVALID_SOCKET)
     {
          std::cerr << "Raw socket creation failed: " << WSAGetLastError() << std::endl;
          WSACleanup();
          return INVALID_SOCKET;
     }

     // Enable IP header inclusion
     BOOL opt = TRUE;
     if (setsockopt(rawSocket, IPPROTO_IP, IP_HDRINCL,
                    (char *)&opt, sizeof(opt)) == SOCKET_ERROR)
     {
          std::cerr << "Failed to set IP_HDRINCL: " << WSAGetLastError() << std::endl;
          closesocket(rawSocket);
          WSACleanup();
          return INVALID_SOCKET;
     }

     // Enable broadcast
     if (setsockopt(rawSocket, SOL_SOCKET, SO_BROADCAST,
                    (char *)&opt, sizeof(opt)) == SOCKET_ERROR)
     {
          std::cerr << "Failed to set SO_BROADCAST: " << WSAGetLastError() << std::endl;
     }

     return rawSocket;
}

SOCKET initUdpSocket()
{
     SOCKET udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
     if (udpSocket == INVALID_SOCKET)
     {
          std::cerr << "UDP socket creation failed: " << WSAGetLastError() << std::endl;
     }
     return udpSocket;
}

void sendToServer(SOCKET udpSocket, const char *buffer, int bytesRead)
{
     sockaddr_in serverAddr;
     serverAddr.sin_family = AF_INET;
     serverAddr.sin_port = htons(SERVER_PORT);
     serverAddr.sin_addr.s_addr = inet_addr(SERVER_IP);

     if (sendto(udpSocket, buffer, bytesRead, 0,
                (sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
     {
          std::cerr << "Failed to send packet to server: " << WSAGetLastError() << std::endl;
     }
}

void processAndForwardPacket(SOCKET rawSocket, SOCKET udpSocket, char *buffer, DWORD bytesRead)
{
     std::cout << "\nForwarding packet of size: " << bytesRead << " bytes" << std::endl;
     debugPacket(buffer, bytesRead);

     // Forward to UDP server unconditionally
     sendToServer(udpSocket, buffer, bytesRead);

     // For raw socket forwarding
     if (bytesRead > 0)
     {
          // Check if this might be an IP packet
          bool isIPPacket = (bytesRead >= sizeof(IPHeader) &&
                             (reinterpret_cast<IPHeader *>(buffer)->versionAndHeaderLength >> 4) == 4);

          sockaddr_in destAddr{};
          destAddr.sin_family = AF_INET;

          if (isIPPacket)
          {
               // Forward IP packet to its intended destination
               IPHeader *ipHeader = reinterpret_cast<IPHeader *>(buffer);
               destAddr.sin_addr.s_addr = ipHeader->destIP;
               std::cout << "Forwarding IP packet to: " << inet_ntoa(destAddr.sin_addr) << std::endl;
          }
          else
          {
               // For non-IP packets, send to broadcast address
               // You might want to change this to a specific network address
               destAddr.sin_addr.s_addr = inet_addr("255.255.255.255");
               std::cout << "Forwarding non-IP packet to broadcast" << std::endl;
          }

          if (sendto(rawSocket, buffer, bytesRead, 0,
                     (sockaddr *)&destAddr, sizeof(destAddr)) == SOCKET_ERROR)
          {
               int error = WSAGetLastError();
               std::cerr << "Raw socket send failed: " << error << " - ";
               switch (error)
               {
               case WSAENETUNREACH:
                    std::cerr << "Network unreachable";
                    break;
               case WSAEHOSTUNREACH:
                    std::cerr << "Host unreachable";
                    break;
               case WSAEACCES:
                    std::cerr << "Permission denied";
                    break;
               default:
                    std::cerr << "Unknown error";
               }
               std::cerr << std::endl;
          }
          else
          {
               std::cout << "Successfully forwarded " << bytesRead << " bytes" << std::endl;
          }
     }
}

void interceptAndForwardPackets(HANDLE tapHandle, SOCKET rawSocket, SOCKET udpSocket)
{
     char buffer[BUFFER_SIZE];
     OVERLAPPED overlapped{};
     overlapped.hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);

     if (!overlapped.hEvent)
     {
          std::cerr << "Failed to create event: " << getLastErrorMessage() << std::endl;
          return;
     }

     while (true)
     {
          DWORD bytesRead;
          if (!ReadFile(tapHandle, buffer, BUFFER_SIZE, &bytesRead, &overlapped))
          {
               if (GetLastError() != ERROR_IO_PENDING)
               {
                    std::cerr << "Read failed: " << getLastErrorMessage() << std::endl;
                    return;
               }

               WaitForSingleObject(overlapped.hEvent, INFINITE);
               if (!GetOverlappedResult(tapHandle, &overlapped, &bytesRead, FALSE))
               {
                    std::cerr << "GetOverlappedResult failed: " << getLastErrorMessage() << std::endl;
                    return;
               }
          }

          processAndForwardPacket(rawSocket, udpSocket, buffer, bytesRead);
     }
}

int main()
{
     std::cout << "Starting packet forwarder..." << std::endl;
     std::cout << "Note: This program requires administrator privileges." << std::endl;

     HANDLE tapHandle = openTapDevice(TAP_DEVICE_GUID);
     if (tapHandle == nullptr)
          return 1;

     if (!configureTapDevice(tapHandle))
          return 1;

     SOCKET rawSocket = initRawSocket();
     if (rawSocket == INVALID_SOCKET)
          return 1;

     SOCKET udpSocket = initUdpSocket();
     if (udpSocket == INVALID_SOCKET)
          return 1;

     std::cout << "Initialization complete. Beginning to intercept and forward packets..."
               << std::endl;

     interceptAndForwardPackets(tapHandle, rawSocket, udpSocket);

     closesocket(rawSocket);
     closesocket(udpSocket);
     CloseHandle(tapHandle);
     WSACleanup();
     return 0;
}