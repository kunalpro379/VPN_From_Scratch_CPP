#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

#define PORT 8081 // Change this to your desired port

void startVPNServer()
{
     WSADATA wsaData;
     SOCKET serverSocket, clientSocket;
     sockaddr_in serverAddr, clientAddr;
     int clientAddrSize = sizeof(clientAddr);
     char buffer[1024];

     // Initialize Winsock
     if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
     {
          std::cerr << "WSAStartup failed\n";
          return;
     }

     // Create socket
     serverSocket = socket(AF_INET, SOCK_STREAM, 0);
     if (serverSocket == INVALID_SOCKET)
     {
          std::cerr << "Error creating socket: " << WSAGetLastError() << "\n";
          WSACleanup();
          return;
     }

     // Setup server address
     serverAddr.sin_family = AF_INET;
     serverAddr.sin_port = htons(PORT);
     serverAddr.sin_addr.s_addr = INADDR_ANY;

     // Bind socket
     if (bind(serverSocket, (sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
     {
          std::cerr << "Binding failed with error: " << WSAGetLastError() << "\n";
          closesocket(serverSocket);
          WSACleanup();
          return;
     }

     // Listen for connections
     if (listen(serverSocket, 5) == SOCKET_ERROR)
     {
          std::cerr << "Listen failed with error: " << WSAGetLastError() << "\n";
          closesocket(serverSocket);
          WSACleanup();
          return;
     }

     std::cout << "VPN Server is listening on port " << PORT << "...\n";

     // Accept client connection
     clientSocket = accept(serverSocket, (sockaddr *)&clientAddr, &clientAddrSize);
     if (clientSocket == INVALID_SOCKET)
     {
          std::cerr << "Accept failed with error: " << WSAGetLastError() << "\n";
          closesocket(serverSocket);
          WSACleanup();
          return;
     }

     std::cout << "Client connected from " << inet_ntoa(clientAddr.sin_addr) << "\n";

     // Receive data from the client
     int bytesReceived;
     while ((bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0)) > 0)
     {
          std::cout << "Received: " << std::string(buffer, bytesReceived) << "\n";
     }

     if (bytesReceived == SOCKET_ERROR)
     {
          std::cerr << "Receive failed with error: " << WSAGetLastError() << "\n";
     }

     std::cout << "Closing connection...\n";
     closesocket(clientSocket);
     closesocket(serverSocket);
     WSACleanup();
}

int main()
{
     startVPNServer();
     return 0;
}
