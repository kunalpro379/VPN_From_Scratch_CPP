
// Config.cpp
#include "./Include/Config.hpp"
#include <iostream>
#include <mutex>

std::unique_ptr<Config> Config::instance;
//std::mutex Config::mutex;

Config::Config()
{
    loadDefaults();
}

void Config::loadDefaults()
{
    server_port = 8080;
    server_address = "127.0.0.1";
    session_timeout_seconds = 300;
    max_sessions = 1000;
    encryption_key = "default_key";
    key_rotation_interval = 3600;
    log_path = "logs/";
    config_path = "config/";
}

bool Config::loadFromFile(const std::string &path)
{
    try
    {
        std::ifstream file(path);
        if (!file.is_open())
        {
            std::cerr << "Failed to open config file: " << path << std::endl;
            return false;
        }

        // Here you would implement actual file reading logic
        // For example, using JSON:
        /*
        Json::Value root;
        file >> root;

        server_port = root["server_port"].asInt();
        server_address = root["server_address"].asString();
        session_timeout_seconds = root["session_timeout"].asInt();
        max_sessions = root["max_sessions"].asInt();
        encryption_key = root["encryption_key"].asString();
        key_rotation_interval = root["key_rotation_interval"].asInt();
        */

        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error loading config: " << e.what() << std::endl;
        return false;
    }
}

bool Config::saveToFile(const std::string &path)
{
    try
    {
        std::ofstream file(path);
        if (!file.is_open())
        {
            std::cerr << "Failed to open config file for writing: " << path << std::endl;
            return false;
        }

        // Here you would implement actual file writing logic
        // For example, using JSON:
        /*
        Json::Value root;
        root["server_port"] = server_port;
        root["server_address"] = server_address;
        root["session_timeout"] = session_timeout_seconds;
        root["max_sessions"] = max_sessions;
        root["encryption_key"] = encryption_key;
        root["key_rotation_interval"] = key_rotation_interval;

        file << root.toStyledString();
        */

        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error saving config: " << e.what() << std::endl;
        return false;
    }
}