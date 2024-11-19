#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>
#include <vector>
#include <chrono>
#include <random>

class Utils {
public:
    // String operations
    static std::vector<std::string> split(const std::string& str, char delimiter);
    static std::string trim(const std::string& str);
    static bool startsWith(const std::string& str, const std::string& prefix);
    static bool endsWith(const std::string& str, const std::string& suffix);
    
    // Random/Crypto utilities
    static std::string generateUUID();
    static std::string generateRandomString(size_t length);
    static std::vector<uint8_t> generateRandomBytes(size_t length);
    
    // Time utilities
    static std::string getTimestamp();
    static int64_t getCurrentTimeMillis();
    static std::string formatDuration(std::chrono::seconds duration);
    
    // File/Path utilities 
    static bool createDirectory(const std::string& path);
    static bool fileExists(const std::string& path);
    static std::string getFileExtension(const std::string& path);
    static std::string joinPaths(const std::string& path1, const std::string& path2);
    
    // Network utilities
    static bool isValidIPAddress(const std::string& ip);
    static bool isValidPort(int port);
    static std::string ipToString(uint32_t ip);
    static uint32_t stringToIP(const std::string& ip);

private:
    static std::random_device rd;
    static std::mt19937 gen;
};

#endif // UTILS_HPP
