#ifndef SESSION_MANAGER_HPP
#define SESSION_MANAGER_HPP

#include <string>
#include <memory>
#include <chrono>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <atomic>
#include "Config.hpp"
using namespace std;

// Forward declare Config since we only need pointer/reference

class Session
{
public:
     std::string sessionId;
     std::chrono::system_clock::time_point lastActivity;
     bool isValid() const;
     void refresh();
};

class SessionManager
{
private:
     // Store active sessions with thread-safe map
     std::unordered_map<std::string, std::shared_ptr<Session>> activeSessions;
     std::mutex sessionMutex;

     // Configuration
     // std::shared_ptr<Config> config;

     // Monitoring
     std::atomic<bool> isRunning{false};
     std::unique_ptr<SessionMonitor> monitor;

public:
     SessionManager();
     ~SessionManager();

     // Session management
     std::shared_ptr<Session> createSession(const std::string &clientId,
                                            const std::string &sourceIp,
                                            int sourcePort,
                                            const std::string &destIp,
                                            int destPort);

     void closeSession(const std::string &sessionId);
     void closeAllSessions();

     // Session lookup
     std::shared_ptr<Session> getSession(const std::string &sessionId);
     std::vector<std::shared_ptr<Session>> getActiveSessions();

     // Session monitoring
     void startMonitoring();
     void stopMonitoring();

     // Session cleanup
     void cleanupInactiveSessions(std::chrono::seconds timeout = std::chrono::seconds(300));

private:
     // Helper methods
     std::string generateSessionId();
     void removeSession(const std::string &sessionId);
     bool validateSession(const Session &session);
     void logSessionActivity(const std::string &sessionId, const std::string &activity);
};

#endif // SESSION_MANAGER_HPP