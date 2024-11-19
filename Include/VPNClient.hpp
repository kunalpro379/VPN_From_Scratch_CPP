#ifndef VPN_CLIENT_H
#define VPN_CLIENT_H

#include <string>
#include <atomic>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

class VPNClient
{
private:
     std::string serverAddr;
     int serverPort;
     std::string username;
     std::string password;
     SOCKET clientSocket;
     std::atomic<bool> isConnected{false};

public:
     VPNClient(const std::string &serverAddr, int serverPort,
               const std::string &username, const std::string &password);
     ~VPNClient();

     bool connectToVPN();
     void startVPNSession();
     void disconnectFromVPN();
     bool isConnectionActive() const { return isConnected; }

private:
     void cleanupResources();
};

#endif // _WIN32
#endif // VPN_CLIENT_H