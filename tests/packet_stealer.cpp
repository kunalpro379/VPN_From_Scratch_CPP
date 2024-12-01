#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <cstring>
#include <algorithm>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

class PacketStealer {
private:
    static const int MAX_PACKET_SIZE = 65535;
    bool running;

    void printPacketContents(const unsigned char* packet, int length, int ipHeaderLen) {
        // Skip IP header to get to TCP/UDP data
        const unsigned char* data = packet + ipHeaderLen;
        int dataLen = length - ipHeaderLen;

        // Print as ASCII if it looks like text
        std::cout << "\nPacket Contents:" << std::endl;
        std::cout << "ASCII:" << std::endl;
        for (int i = 0; i < dataLen; i++) {
            char c = data[i];
            if (isprint(c)) {
                std::cout << c;
            } else {
                std::cout << '.';
            }
        }
        std::cout << std::endl;

        // Print as hex
        std::cout << "\nHex dump:" << std::endl;
        for (int i = 0; i < dataLen; i++) {
            if (i % 16 == 0) std::cout << "  ";
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << (int)data[i] << " ";
            if ((i + 1) % 16 == 0) std::cout << std::endl;
        }
        std::cout << std::dec << std::endl;
    }

    bool isWebTraffic(unsigned short port) {
        // Common web ports (HTTP, HTTPS, etc)
        return port == 80 || port == 443 || port == 8080;
    }

    void analyzePacket(const unsigned char* packet, int length) {
        // Get IP header length
        unsigned char ihl = packet[0] & 0xF;
        int ipHeaderLen = ihl * 4;

        // Get protocol
        unsigned char protocol = packet[9];
        
        // Get source and destination IPs
        unsigned int srcIP = *(unsigned int*)(packet + 12);
        unsigned int dstIP = *(unsigned int*)(packet + 16);
        
        // Convert IPs to string
        in_addr src, dst;
        src.s_addr = srcIP;
        dst.s_addr = dstIP;

        // For TCP/UDP packets, get ports
        if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
            unsigned short srcPort = ntohs(*(unsigned short*)(packet + ipHeaderLen));
            unsigned short dstPort = ntohs(*(unsigned short*)(packet + ipHeaderLen + 2));

            // Only show web traffic
            if (isWebTraffic(srcPort) || isWebTraffic(dstPort)) {
                std::cout << "\n=== Intercepted Web Traffic ===" << std::endl;
                std::cout << "Protocol: " << (protocol == IPPROTO_TCP ? "TCP" : "UDP") << std::endl;
                std::cout << "From: " << inet_ntoa(src) << ":" << srcPort << std::endl;
                std::cout << "To: " << inet_ntoa(dst) << ":" << dstPort << std::endl;
                std::cout << "Size: " << length << " bytes" << std::endl;
                
                // Print actual packet contents
                printPacketContents(packet, length, ipHeaderLen);
                std::cout << "=============================" << std::endl;
            }
        }
    }

public:
    PacketStealer() : running(false) {}

    bool start() {
        // Initialize Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "Failed to initialize Winsock" << std::endl;
            return false;
        }

        // Create a raw socket
        SOCKET rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
        if (rawSocket == INVALID_SOCKET) {
            std::cerr << "Failed to create raw socket. Error: " << WSAGetLastError() << std::endl;
            std::cerr << "Make sure you're running as Administrator!" << std::endl;
            return false;
        }

        // Get local IP address
        char hostName[256];
        if (gethostname(hostName, sizeof(hostName)) == SOCKET_ERROR) {
            std::cerr << "Failed to get hostname" << std::endl;
            return false;
        }

        struct hostent* phe = gethostbyname(hostName);
        if (phe == NULL) {
            std::cerr << "Failed to get host info" << std::endl;
            return false;
        }

        // Bind to first available interface
        SOCKADDR_IN sa;
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = ((struct in_addr*)phe->h_addr_list[0])->s_addr;
        sa.sin_port = 0;

        if (bind(rawSocket, (SOCKADDR*)&sa, sizeof(sa)) == SOCKET_ERROR) {
            std::cerr << "Failed to bind socket. Error: " << WSAGetLastError() << std::endl;
            return false;
        }

        // Set socket to promiscuous mode
        DWORD optval = 1;
        if (ioctlsocket(rawSocket, SIO_RCVALL, &optval) == SOCKET_ERROR) {
            std::cerr << "Failed to set promiscuous mode. Error: " << WSAGetLastError() << std::endl;
            return false;
        }

        running = true;
        std::cout << "Started packet interception. Capturing web traffic..." << std::endl;
        std::cout << "Try browsing some websites to see the packets!" << std::endl;

        // Capture packets
        std::vector<unsigned char> buffer(MAX_PACKET_SIZE);
        while (running) {
            int bytesRead = recv(rawSocket, (char*)buffer.data(), buffer.size(), 0);
            if (bytesRead > 0) {
                analyzePacket(buffer.data(), bytesRead);
            }
        }

        closesocket(rawSocket);
        WSACleanup();
        return true;
    }

    void stop() {
        running = false;
    }
};

int main() {
    std::cout << "Starting Web Traffic Stealer..." << std::endl;
    std::cout << "WARNING: This program requires administrator privileges!" << std::endl;
    std::cout << "WARNING: Only use this for educational purposes!" << std::endl;
    
    PacketStealer stealer;
    if (!stealer.start()) {
        std::cerr << "Failed to start packet stealer" << std::endl;
        return 1;
    }
    return 0;
}
