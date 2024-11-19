// #include <winsock2.h>
// #include <windows.h>
// #include <iostream>
// #include <string>
// #include <iomanip> // For setw, setfill, hex, etc.

// #pragma comment(lib, "ws2_32.lib")

// #define SERVER_PORT 12345 // Define your server port

// // Function to initialize server socket
// SOCKET initServerSocket()
// {
//      WSADATA wsaData;
//      if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
//      {
//           std::cerr << "WSAStartup failed with error code: " << WSAGetLastError() << std::endl;
//           return INVALID_SOCKET;
//      }

//      SOCKET serverSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); // Use SOCK_DGRAM for UDP
//      if (serverSocket == INVALID_SOCKET)
//      {
//           std::cerr << "Socket creation failed with error code: " << WSAGetLastError() << std::endl;
//           WSACleanup();
//           return INVALID_SOCKET;
//      }

//      // Set up server address structure
//      sockaddr_in serverAddr;
//      serverAddr.sin_family = AF_INET;
//      serverAddr.sin_port = htons(SERVER_PORT);
//      serverAddr.sin_addr.s_addr = INADDR_ANY;

//      // Bind the socket
//      if (bind(serverSocket, (sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
//      {
//           std::cerr << "Bind failed with error code: " << WSAGetLastError() << std::endl;
//           closesocket(serverSocket);
//           WSACleanup();
//           return INVALID_SOCKET;
//      }

//      std::cout << "Server initialized and listening on port " << SERVER_PORT << std::endl;
//      return serverSocket;
// }

// // Function to print the packet content
// void printPacketHex(const char *buffer, int length)
// {
//      for (int i = 0; i < length; i++)
//      {
//           std::cout << std::hex << std::setw(2) << std::setfill('0')
//                     << (int)(unsigned char)buffer[i] << " ";
//           if ((i + 1) % 16 == 0)
//                std::cout << std::endl;
//      }
//      std::cout << std::dec << std::endl;
// }

// // Main server loop
// void receiveAndPrintPackets(SOCKET serverSocket)
// {
//      char buffer[1500]; // Buffer to store the incoming packets
//      sockaddr_in clientAddr;
//      int clientAddrSize = sizeof(clientAddr);

//      while (true)
//      {
//           int bytesReceived = recvfrom(serverSocket, buffer, sizeof(buffer), 0, (sockaddr *)&clientAddr, &clientAddrSize);
//           if (bytesReceived == SOCKET_ERROR)
//           {
//                std::cerr << "recvfrom failed with error code: " << WSAGetLastError() << std::endl;
//                break;
//           }

//           printPacket(buffer, bytesReceived); // Print the received packet
//      }
// }
// int main()
// {
//      WSADATA wsaData;
//      if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
//      {
//           std::cerr << "WSAStartup failed" << std::endl;
//           return 1;
//      }

//      // Create UDP socket
//      SOCKET serverSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
//      if (serverSocket == INVALID_SOCKET)
//      {
//           std::cerr << "Socket creation failed" << std::endl;
//           WSACleanup();
//           return 1;
//      }

//      // Bind socket
//      sockaddr_in serverAddr{};
//      serverAddr.sin_family = AF_INET;
//      serverAddr.sin_port = htons(SERVER_PORT);
//      serverAddr.sin_addr.s_addr = INADDR_ANY;

//      if (bind(serverSocket, (sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
//      {
//           std::cerr << "Bind failed with error: " << WSAGetLastError() << std::endl;
//           closesocket(serverSocket);
//           WSACleanup();
//           return 1;
//      }

//      std::cout << "Server listening on port " << SERVER_PORT << std::endl;

//      // Receive packets
//      char buffer[BUFFER_SIZE];
//      sockaddr_in clientAddr{};
//      int clientAddrLen = sizeof(clientAddr);

//      while (true)
//      {
//           int bytesReceived = recvfrom(serverSocket, buffer, BUFFER_SIZE, 0,
//                                        (sockaddr *)&clientAddr, &clientAddrLen);

//           if (bytesReceived == SOCKET_ERROR)
//           {
//                std::cerr << "recvfrom failed with error: " << WSAGetLastError() << std::endl;
//                continue;
//           }

//           // Get client IP
//           char clientIP[INET_ADDRSTRLEN];
//           inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, INET_ADDRSTRLEN);

//           std::cout << "\nReceived " << bytesReceived << " bytes from " << clientIP << ":"
//                     << ntohs(clientAddr.sin_port) << std::endl;

//           // Print packet contents
//           printPacketHex(buffer, bytesReceived);
//      }

//      closesocket(serverSocket);
//      WSACleanup();
//      return 0;
// }

#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <iomanip>
#include <ws2tcpip.h> // For inet_ntop and other utilities

#pragma comment(lib, "ws2_32.lib")

#define SERVER_PORT 12345 // Define your server port
#define BUFFER_SIZE 1500  // Define buffer size

// Function to initialize server socket
SOCKET initServerSocket()
{
     WSADATA wsaData;
     if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
     {
          std::cerr << "WSAStartup failed with error code: " << WSAGetLastError() << std::endl;
          return INVALID_SOCKET;
     }

     SOCKET serverSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
     if (serverSocket == INVALID_SOCKET)
     {
          std::cerr << "Socket creation failed with error code: " << WSAGetLastError() << std::endl;
          WSACleanup();
          return INVALID_SOCKET;
     }

     sockaddr_in serverAddr;
     serverAddr.sin_family = AF_INET;
     serverAddr.sin_port = htons(SERVER_PORT);
     serverAddr.sin_addr.s_addr = INADDR_ANY;

     if (bind(serverSocket, (sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
     {
          std::cerr << "Bind failed with error code: " << WSAGetLastError() << std::endl;
          closesocket(serverSocket);
          WSACleanup();
          return INVALID_SOCKET;
     }

     std::cout << "Server initialized and listening on port " << SERVER_PORT << std::endl;
     return serverSocket;
}

void printPacketHex(const char *buffer, int length)
{
     for (int i = 0; i < length; i++)
     {
          std::cout << std::hex << std::setw(2) << std::setfill('0')
                    << (int)(unsigned char)buffer[i] << " ";
          if ((i + 1) % 16 == 0)
               std::cout << std::endl;
     }
     std::cout << std::dec << std::endl;
}

int main()
{
     SOCKET serverSocket = initServerSocket();
     if (serverSocket == INVALID_SOCKET)
          return 1;

     char buffer[BUFFER_SIZE];
     sockaddr_in clientAddr{};
     int clientAddrLen = sizeof(clientAddr);

     while (true)
     {
          int bytesReceived = recvfrom(serverSocket, buffer, BUFFER_SIZE, 0,
                                       (sockaddr *)&clientAddr, &clientAddrLen);

          if (bytesReceived == SOCKET_ERROR)
          {
               std::cerr << "recvfrom failed with error: " << WSAGetLastError() << std::endl;
               continue;
          }

          // Get client IP (fallback to inet_ntoa if inet_ntop isn't available)
          // char clientIP[INET_ADDRSTRLEN];
          // inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, INET_ADDRSTRLEN);
          char *clientIP = inet_ntoa(clientAddr.sin_addr);

          std::cout << "\nReceived " << bytesReceived << " bytes from " << clientIP << ":"
                    << ntohs(clientAddr.sin_port) << std::endl;

          printPacketHex(buffer, bytesReceived);
     }

     closesocket(serverSocket);
     WSACleanup();
     return 0;
}
