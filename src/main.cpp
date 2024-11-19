#include "VPNClient.h"
#include "VPNServer.h"
#include "Config.h"
#include "Utils.h"

#include <iostream>
#include <thread>

void runServer() {
    int serverPort = Config::getDefaultServerPort();
    VPNServer server(serverPort);

    std::cout << "Starting VPN Server...\n";
    server.startServer();
}

void runClient(const std::string& serverAddress, int serverPort) {
    std::string username = "testuser"; 
    std::string password = "secured_password";

    VPNClient client(serverAddress, serverPort, username, password);

    std::cout << "Attempting to connect to the VPN server...\n";
    if (client.connectToVPN()) {
        std::cout << "VPN Client connected successfully. Starting session...\n";
        std::thread receiveThread(&VPNClient::receiveAndDecryptFromServer, &client);

        // This will block and handle data transmission until terminated
        client.startVPNSession();

        // Join receive thread when done (if ever reached)
        if (receiveThread.joinable()) {
            receiveThread.join();
        }
    } else {
        std::cerr << "Failed to connect to the VPN server.\n";
    }
}

int main() {
    std::cout << "Welcome to the VPN Client-Server System\n\n";
    std::cout << "1. Start as Server\n";
    std::cout << "2. Start as Client\n";
    std::cout << "Enter your choice: ";
    
    int choice;
    std::cin >> choice;

    if (choice == 1) {
        std::thread serverThread(runServer);
        serverThread.join();
    } else if (choice == 2) {
        std::string serverAddress = Config::getDefaultServerAddress();
        int serverPort = Config::getDefaultServerPort();

        runClient(serverAddress, serverPort);
    } else {
        std::cerr << "Invalid choice. Exiting...\n";
    }

    return 0;
}
