#ifndef ENCRYPTION_HPP
#define ENCRYPTION_HPP

#include <string>

class Encryption
{
public:
     enum class Algorithm
     {
          XOR,
          AES256,
          ChaCha20
     };

     // Add initialization vector support
     void setIV(const std::string &iv);

     // Add key rotation support
     void rotateKey();

     // Add encryption strength validation
     bool validateKeyStrength() const;
     Encryption();
     string encryptData(const string &data);
     string decryptData(const string &data);

private:
     // generate a random key
     string key;
     string xorEncryptDecrypt(const string &data, const string &key);
};
#endif
