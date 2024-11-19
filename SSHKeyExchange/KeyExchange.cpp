#include "../Include/keyexchange.hpp"
#include <iostream>
#include <cstdlib> // For rand()
#include <ctime> // For time()
using namespace std;
KeyExchange::KeyExchange(){
     //Initializing random for generating keys
     srand(time(NULL));
     sharedSecretKey = generateSharedSecretKey();
}

bool KeyExchange::performKeyExchange(const string& serverAddr){
     return true;
}

bool KeyExchange::performKeyExchange(int clientSocket){
     return true;
}

string KeyExchange::getSharedSecretKey() const{
     return sharedSecretKey;
}

string KeyExchange::generateSharedSecretKey(){
     return "test_key"; 
}
