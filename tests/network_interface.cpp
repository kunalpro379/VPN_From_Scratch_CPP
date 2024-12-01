#include <windows.h>
#include <iostream>
#include <windivert.h>
#include <thread>
#include <atomic>

#pragma comment(lib, "WinDivert.lib")

class NetworkInterface {
private:
    HANDLE divertHandle;
    std::atomic<bool> running;
    static const int MAX_PACKET_SIZE = 65535;

    void processPacket(char* packet, UINT packetLen, WINDIVERT_ADDRESS* addr) {
        // Here you can modify the packet before forwarding
        // For now, we'll just print and forward it
        std::cout << "Intercepted packet of size: " << packetLen << std::endl;
        
        // Forward the packet
        UINT writeLen = 0;
        WinDivertSend(divertHandle, packet, packetLen, addr, &writeLen);
    }

public:
    NetworkInterface() : running(false), divertHandle(INVALID_HANDLE_VALUE) {}

    bool start() {
        // Open WinDivert handle to capture all traffic
        divertHandle = WinDivertOpen(
            "true",  // Capture all packets
            WINDIVERT_LAYER_NETWORK,
            0,  // Priority
            WINDIVERT_FLAG_SNIFF  // Sniff mode: don't drop packets
        );

        if (divertHandle == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to open WinDivert handle. Error: " << GetLastError() << std::endl;
            return false;
        }

        running = true;
        std::thread captureThread([this]() {
            char packet[MAX_PACKET_SIZE];
            UINT packetLen;
            WINDIVERT_ADDRESS addr;

            while (running) {
                if (WinDivertRecv(divertHandle, packet, sizeof(packet), &packetLen, &addr)) {
                    processPacket(packet, packetLen, &addr);
                }
            }
        });
        captureThread.detach();

        return true;
    }

    void stop() {
        running = false;
        if (divertHandle != INVALID_HANDLE_VALUE) {
            WinDivertClose(divertHandle);
            divertHandle = INVALID_HANDLE_VALUE;
        }
    }

    ~NetworkInterface() {
        stop();
    }
};

int main() {
    // Ensure running as administrator
    if (!IsUserAnAdmin()) {
        std::cerr << "This program must be run as administrator!" << std::endl;
        return 1;
    }

    NetworkInterface interface;
    if (!interface.start()) {
        std::cerr << "Failed to start network interface" << std::endl;
        return 1;
    }

    std::cout << "Network interface started. Press Enter to stop..." << std::endl;
    std::cin.get();

    interface.stop();
    return 0;
}
