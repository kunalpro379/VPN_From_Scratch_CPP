// #ifndef VPN_CLIENT_H
// #define VPN_CLIENT_H
// #include "Tunneling.hpp"
// #include "Encryption.hpp"
// #include "NetworkInterface.hpp"
// #include "Authentication.hpp"
// #include "KeyExchange.hpp"

// #include <thread>
// #include <vector>
// #include <string>
// #include <memory>
// #include <functional>
// #include <atomic>

// using namespace std;
// class NetworkError;
// class Logger;
// class VPNClient
// {
// private:
//      string serverAddr;
//      int serverPort;
//      string username;
//      string password;
//      std::unique_ptr<Encryption> encryption;
//      std::unique_ptr<KeyExchange> keyExchange;
//      NetworkInterface networkInterface;
//      Tunneling tunneling;
//      Authentication authentication;
//      std::atomic<bool> isConnected{false};
//      std::function<void(const std::string &)> statusCallback;
//      std::unique_ptr<Logger> logger;
//      // thread receiveThread;

// public:
//      VPNClient(const string &serverAddr, int serverPort,
//                const string &username, const string &password);
//      ~VPNClient();

//      // Core VPN functionality
//      bool ConnectToVPN();
//      void StartVPNSession();
//      void DisconnectFromVPN();
//      bool isConnectionActive() const { return isConnected; }

//      // Network operations
//      void receiveAndDecryptFromServer();
//      void handleConnectionFailure(const NetworkError &error);
//      // void logActivity(const std::string &activity, LogLevel level);

//      // Status and error handling
//      struct VPNError
//      {
//           int code;
//           std::string message;
//           std::string timestamp;

//           VPNError(int c, const std::string &msg) : code(c), message(msg)
//           {
//                // Add timestamp
//           }
//      };

//      void setStatusCallback(std::function<void(const std::string &)> callback)
//      {
//           statusCallback = callback;
//      }

// private:
//      bool performKeyExchange();
//      bool authenticateWithServer();
//      void initializeEncryption();
//      void setupTunnel();
//      void monitorConnection();
//      void cleanupResources();
// };

// #endif // VPN_CLIENT_H