// VPNServer.cpp
#include "../Include/VPNServer.hpp"
#include "../Include/Config.hpp"
#include "../Include/SessionManager.hpp"
#include "../Include/LoadBalancer.hpp"
#include "../Include/Authentication.hpp"
#include "../Include/KeyExchange.hpp"
#include "../Include/NetworkInterface.hpp"
#include "../Include/Tunneling.hpp"
#include <iostream>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <unistd.h>
#include <vector>
#include <thread>
using namespace std;
VPNServer::VPNServer(int port) : server_port(port), isRunning(false)
{
     config = &Config::getInstance();

     // Initialize components
     if (port != 0)
     {
          server_port = port;
     }
     else
     {
          server_port = config->getServerPort();
     }

     // loadBalancer = make_unique<LoadBalancer>();
     /*
     sessionManager = make_unique<SessionManager>();
     encryption = make_unique<Encryption>();
     keyExchange = make_unique<KeyExchange>();
     authentication = make_unique<Authentication>();
     networkInterface = make_unique<NetworkInterface>();
     tunneling = make_unique<Tunneling>();
*/
}

VPNServer::~VPNServer()
{
     isRunning = false;

     // Wait for all client threads to complete
     for (thread &thread : clientThreads)
     {
          if (thread.joinable())
          {
               thread.join();
          }
     }

     // Cleanup cluster nodes
     // clusterNodes.clear();
}

void VPNServer::StartServer()
{
     if (isRunning)
     {
          cout << "Server already running" << endl;
          return;
     }

     WSADATA wsaData;
     if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
     {
          cerr << "WSAStartup failed" << endl;
          return;
     }

     int server_socket = socket(AF_INET, SOCK_STREAM, 0);
     if (server_socket < 0)
     {
          cerr << "Failed to create server socket" << endl;
          WSACleanup();
          return;
     }

     int opt = 1;
     if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt)) < 0)
     {
          cerr << "Error setting socket options" << endl;
          closesocket(server_socket);
          WSACleanup();
          return;
     }

     struct sockaddr_in server_addr;
     memset(&server_addr, 0, sizeof(server_addr));
     server_addr.sin_family = AF_INET;
     server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
     server_addr.sin_port = htons(server_port);

     if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
     {
          cerr << "Error binding socket to port " << server_port << endl;
          closesocket(server_socket);
          WSACleanup();
          return;
     }

     if (listen(server_socket, SOMAXCONN) < 0)
     {
          cerr << "Error listening on socket" << endl;
          closesocket(server_socket);
          WSACleanup();
          return;
     }

     isRunning = true;
     cout << "Server started on port " << server_port << endl;

     while (isRunning)
     {
          struct sockaddr_in client_addr;
          int client_len = sizeof(client_addr);

          int client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
          if (client_socket < 0)
          {
               cerr << "Error accepting client connection" << endl;
               continue;
          }

          // Create new thread to handle the connection
          std::thread client_thread(&VPNServer::HandleClientConnection, this, client_socket);
          client_thread.detach();

          // clientThreads.emplace_back(&VPNServer::HandleClientConnection, this, client_socket);
     }

     closesocket(server_socket);
     WSACleanup();
}
/*
void VPNServer::HandleClientConnection(int clientSocket)
{
     if (!authenticateClient(clientSocket))
     {
          cerr << "Client authentication failed" << endl;
          closesocket(clientSocket);
          return;
     }

     if (!performKeyExchange(clientSocket))
     {
          cerr << "Key exchange failed" << endl;
          closesocket(clientSocket);
          return;
     }

     // Create VPN tunnel
     if (!tunneling->createTunnel(clientSocket))
     {
          cerr << "Failed to create VPN tunnel" << endl;
          closesocket(clientSocket);
          return;
     }

     // Main communication loop
     char buffer[4096];
     while (isRunning)
     {
          memset(buffer, 0, sizeof(buffer));
          int bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

          if (bytesRead <= 0)
          {
               break;
          }

          // Process and forward the tunneled data
          string processedData = tunneling->processData(buffer, bytesRead);
          send(clientSocket, processedData.c_str(), processedData.length(), 0);
     }

     tunneling->closeTunnel(clientSocket);
     closesocket(clientSocket);
}

bool VPNServer::performKeyExchange(int clientSocket)
{
     return keyExchange->performExchange(clientSocket);
}

bool VPNServer::authenticateClient(int clientSocket)
{
     return authentication->authenticateClient(clientSocket);
}

void VPNServer::distributeLoad()
{
     loadBalancer->balanceLoad(clusterNodes);
}

void VPNServer::syncClusterState()
{
     for (auto node : clusterNodes)
     {
          // Implement cluster state synchronization
     }
}

void VPNServer::addClusterNode(VPNServer *node)
{
     clusterNodes.push_back(node);
     syncClusterState();
}

void VPNServer::removeClusterNode(VPNServer *node)
{
     auto it = find(clusterNodes.begin(), clusterNodes.end(), node);
     if (it != clusterNodes.end())
     {
          clusterNodes.erase(it);
          syncClusterState();
     }
}

bool VPNServer::validateClusterHealth()
{
     for (auto node : clusterNodes)
     {
          if (!node->isServerHealthy())
          {
               return false;
          }
     }
     return true;
}

void VPNServer::handleClientDisconnect(const string &clientId)
{
     sessionManager->removeSession(clientId);
     cleanupClientResources(clientId);
}

void VPNServer::cleanupClientResources(const string &clientId)
{
     // Implement resource cleanup
}
*/