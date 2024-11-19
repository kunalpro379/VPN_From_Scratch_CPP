// Config.hpp
#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <string>
#include <mutex>
#include <memory>
#include <fstream>
#include <json/json.h> // You'll need to include a JSON library

class Config
{
private:
    Config(); // Private constructor
    static std::unique_ptr<Config> instance;
    //static std::mutex mutex;

    // Network settings
    int server_port{8080};
    std::string server_address{"127.0.0.1"};

    // Session settings
    int session_timeout_seconds{300};
    int max_sessions{1000};

    // Security settings
    std::string encryption_key{"default_key"};
    int key_rotation_interval{3600};

    // Paths
    std::string log_path{"logs/"};
    std::string config_path{"config/"};

    void loadDefaults();

public:
    Config(const Config &) = delete;
    Config &operator=(const Config &) = delete;

    static Config &getInstance()
    {
        //std::lock_guard<std::mutex> lock(mutex);
        if (!instance)
        {
            instance.reset(new Config());
        }
        return *instance;
    }

    // Network settings
    int getServerPort() const { return server_port; }
    std::string getServerAddress() const { return server_address; }

    // Session settings
    int getSessionTimeout() const { return session_timeout_seconds; }
    int getMaxSessions() const { return max_sessions; }

    // Security settings
    std::string getEncryptionKey() const { return encryption_key; }
    int getKeyRotationInterval() const { return key_rotation_interval; }

    // Paths
    std::string getLogPath() const { return log_path; }
    std::string getConfigPath() const { return config_path; }

    bool loadFromFile(const std::string &path);
    bool saveToFile(const std::string &path);
};

#endif // CONFIG_HPP