#ifndef KEYEXCHANGE_HPP
#define KEYEXCHANGE_HPP

#include <string>

class KeyExchange
{
     KeyExchange();
     // FOR CLIENT SIDE
     // to perform key exchange with server
     bool performKeyExchange(const string &serverAddr);
     // FOR SERVER SIDE
     // to perform key exchange with client
     bool performKeyExchange(int clientSocket);

     // Getter for the shared secret key
     string getSharedSecretKey() const;

private:
     string sharedSecretKey;
     string generateSharedSecretKey();
     bool implementDiffieHellman();
     bool implementTLS();
     // Add perfect forward secrecy
     void rotateSessionKeys();
};
#endif
