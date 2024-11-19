#ifndef AUTHENTICATION_H
#define AUTHENTICATION_H

#include <string>

class Authentication {
public:
    // Add virtual destructor for base class
    virtual ~Authentication() = default;
    
    // Add return type for authentication status
    struct AuthResult {
        bool success;
        std::string message;
    };
    
    // Make methods virtual to allow different authentication strategies
    virtual AuthResult authenticateClient(const std::string& username, const std::string& password);
    virtual AuthResult authenticateClient(int clientSocket);
    
private:
    // Add member variables for storing authentication state
    bool isAuthenticated = false;
};

#endif // AUTHENTICATION_H
