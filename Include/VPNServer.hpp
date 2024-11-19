#ifndef VPN_SERVER_H
#define VPN_SERVER_H
// #include "Tunneling.hpp"
// #include "Encryption.hpp"
#include "Utils.hpp"
#include "Config.hpp"

// #include "NetworkInterface.hpp"
// #include "LoadBalancer.hpp"
// #include "SessionManager.hpp"
// #include "Authentication.hpp"
// #include "KeyExchange.hpp"

#include <vector>
#include <string>
#include <mutex>
// Forward declaration
class LoadBalancer;

using namespace std;

// VPN Server class that handles the step-by-step VPN connection process
class VPNServer
{
private:
     // Step 1: Server Configuration
     int server_port;
     Config *config;
     bool isRunning;

     // Step 2: Load Balancing & Clustering
     std::unique_ptr<LoadBalancer> loadBalancer;
     std::vector<VPNServer *> clusterNodes;
     void distributeLoad();
     void syncClusterState();
     void addClusterNode(VPNServer *node);
     void removeClusterNode(VPNServer *node);
     bool validateClusterHealth();

     // Step 3: Client Connection Management
     std::vector<thread> clientThreads;
     // SessionManager sessionManager;

     // // Step 4: Security Components
     // std::unique_ptr<Encryption> encryption;
     // std::unique_ptr<KeyExchange> keyExchange;
     // Authentication authentication;
     // bool performKeyExchange(int clientSocket);
     // bool authenticateClient(int clientSocket);

     // Step 5: Network & Tunneling
     // NetworkInterface networkInterface;
     // Tunneling tunneling;

     // Step 6: Client Session Handling
     // void handleClientDisconnect(const std::string &clientId);
     // void cleanupClientResources(const std::string &clientId);

     // Step 7: Monitoring & Health Checks
     // std::atomic<bool> isHealthy{true};
     // std::function<void(const std::string &)> statusCallback;

public:
     // Step 8: Server Lifecycle Methods
     VPNServer(int port);
     ~VPNServer();
     void StartServer();
     void HandleClientConnection(int clientSocket);
};

#endif // VPN_SERVER_H