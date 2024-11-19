#include "networkinterface.hpp"
#include <iostream>
#include <cstring> // for memset
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
using namespace std;

NetworkInterface::NetworkInterface( ):serverSocket(-1), isConnected(false){}
NetworkInterface::~NetworkInterface(){
     if(isConnected)disconnectFromServer();
}
bool NetworkInterface::connectToServer(const string& serverAddr, int serverPort){

}

void  NetWorkInterface::disconnectFromServer(){

}
string NetworkInterface::readFromInterface(){}
void NetworkInterface::writeToInterface(const string& data){}
string NetworkInterface::readFromServer(){}
void NetworkInterface::writeToServer(const string& data){}
string NetworkInterface::readFromClient(int clientSocket){}
void NetworkInterface::writeToClient(int clientSocket, const string& data){}
