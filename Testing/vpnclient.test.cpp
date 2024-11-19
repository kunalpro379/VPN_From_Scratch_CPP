#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

#define SERVER_IP "127.0.0.1"
#define PORT 8081

void connectToVPNServer()
{
     WSADATA wsaData;
     SOCKET clientSocket;
     sockaddr_in serverAddr;
     const char *message = "Hello from the VPN Client!";

     // Initialize Winsock
     if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
     {
          std::cerr << "WSAStartup failed\n";
          return;
     }

     // Create socket
     clientSocket = socket(AF_INET, SOCK_STREAM, 0);
     if (clientSocket == INVALID_SOCKET)
     {
          std::cerr << "Error creating socket: " << WSAGetLastError() << "\n";
          WSACleanup();
          return;
     }

     // Setup server address
     serverAddr.sin_family = AF_INET;
     serverAddr.sin_port = htons(PORT);

     // Use inet_addr instead of InetPton
     serverAddr.sin_addr.s_addr = inet_addr(SERVER_IP);
     if (serverAddr.sin_addr.s_addr == INADDR_NONE)
     {
          std::cerr << "Invalid address or address not supported\n";
          closesocket(clientSocket);
          WSACleanup();
          return;
     }

     // Connect to server
     if (connect(clientSocket, (sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
     {
          std::cerr << "Connect failed with error: " << WSAGetLastError() << "\n";
          closesocket(clientSocket);
          WSACleanup();
          return;
     }

     std::cout << "Connected to VPN server at " << SERVER_IP << "\n";

     // Send data to server
     if (send(clientSocket, message, strlen(message), 0) == SOCKET_ERROR)
     {
          std::cerr << "Send failed with error: " << WSAGetLastError() << "\n";
     }

     std::cout << "Message sent to VPN server\n";

     // Close the socket
     closesocket(clientSocket);
     WSACleanup();
}

int main()
{
     connectToVPNServer();
     return 0;
}
