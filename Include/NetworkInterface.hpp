#ifndef NETWORKINTERFACE_HPP
#define NETWORKINTERFACE_HPP

#include <string>

class NetworkInterface{
     public:  
     NetworkInterface();
     ~NetworkInterface();
     //establish conn to the vpn server
//CLIENT SIDE
     bool connectToServer() noexcept(false);
     //Disconn from vpn server
     void disconnectFromServer();
     //read data from the virtual network interface

     void writeToInterface();
     //write data to the virtual network interface
     //read data from the server
     std::string readFromServer() noexcept(false);

     //write data to the server
     void writeToServer();

//SERVER SIDE
     //read data from a client 
     std::string readFromCLient();

     //wrote data tp client 
     void writeToClient();

private: 
int server_socket;
int client_socket;
bool isConnected;

struct NetworkError {
    int code;
    std::string message;
};

static constexpr size_t MAX_BUFFER_SIZE = 8192;

void setTimeout(int seconds);

bool isConnectionActive() const;

};
#endif;
