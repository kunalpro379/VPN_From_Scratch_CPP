#include "Include/VPNServer.hpp"
#include <iostream>
#include <string>
#include <csignal>

VPNServer *server = nullptr;

void signalHandler(int signum)
{
     std::cout << "\nSignal (" << signum << ") received. Cleaning up...\n";
     if (server)
     {
          delete server;
     }
     exit(signum);
}

void printUsage()
{
     std::cout << "Usage: vpn_server [port]\n";
     std::cout << "  port: Optional port number (default: 1194)\n";
}

int main(int argc, char *argv[])
{
     signal(SIGINT, signalHandler);
     signal(SIGTERM, signalHandler);

     int port = 1194; // Default VPN port

     // Parse command line arguments
     if (argc > 1)
     {
          try
          {
               port = std::stoi(argv[1]);
               if (port <= 0 || port > 65535)
               {
                    std::cerr << "Error: Port must be between 1 and 65535\n";
                    return 1;
               }
          }
          catch (const std::exception &e)
          {
               std::cerr << "Error parsing port number: " << e.what() << "\n";
               printUsage();
               return 1;
          }
     }

     try
     {
          server = new VPNServer(port);
          std::cout << "Starting VPN Server...\n";
          server->StartServer();
     }
     catch (const std::exception &e)
     {
          std::cerr << "Error: " << e.what() << "\n";
          delete server;
          return 1;
     }

     delete server;
     return 0;
}