#include <winsock2.h>
#include <windows.h>
#include <thread>
#include <queue>
#include <mutex>
#include <string>
#include <stdexcept>
#include <iostream>
#include <vector>
#include <iomanip>
#include "../Tun_Tap/tun_interface.h"

#define TAP_BUFFER_SIZE 2048
#define TAP_CONTROL_CODE(request,method) CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
#define TAP_IOCTL_SET_MEDIA_STATUS TAP_CONTROL_CODE(6, METHOD_BUFFERED)

class WindowsTunInterface {
private:
    TunInterface tun;
    HANDLE tun_handle;
    bool running;
    std::thread process_thread;
    std::queue<std::vector<uint8_t>> packet_queue;
    std::mutex queue_mutex;

    bool configure_tap_device() {
        DWORD len;
        ULONG status = 1;
        if (!DeviceIoControl(tun_handle, TAP_IOCTL_SET_MEDIA_STATUS,
                           &status, sizeof(status),
                           &status, sizeof(status), &len, NULL)) {
            std::cerr << "Failed to set TAP media status" << std::endl;
            return false;
        }
        return true;
    }

    void write_packet(const uint8_t* packet, size_t length) {
        DWORD bytes_written;
        OVERLAPPED overlapped = {0};
        overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        
        if (!WriteFile(tun_handle, packet, length, &bytes_written, &overlapped)) {
            if (GetLastError() != ERROR_IO_PENDING) {
                std::cerr << "WriteFile failed. Error: " << GetLastError() << std::endl;
                return;
            }
            if (!GetOverlappedResult(tun_handle, &overlapped, &bytes_written, TRUE)) {
                std::cerr << "GetOverlappedResult failed. Error: " << GetLastError() << std::endl;
                return;
            }
        }
        
        CloseHandle(overlapped.hEvent);
    }

    void process_packet(const uint8_t* packet, size_t length) {
        // TAP-Windows adds a 4-byte header before the IP packet
        // First 2 bytes: Flags (0x00 0x00 for incoming packets)
        // Next 2 bytes: Protocol (0x08 0x00 for IPv4)
        const size_t TAP_HEADER_SIZE = 4;
        
        if (length < TAP_HEADER_SIZE + 20) { // TAP header + minimum IP header
            std::cerr << "Packet too short: " << length << " bytes" << std::endl;
            return;
        }

        // Skip TAP header to get to IP packet
        const uint8_t* ip_packet = packet + TAP_HEADER_SIZE;
        size_t ip_length = length - TAP_HEADER_SIZE;

        // Verify TAP header protocol (should be 0x0800 for IPv4)
        uint16_t tap_protocol = (packet[2] << 8) | packet[3];
        if (tap_protocol != 0x0800) {
            std::cerr << "Non-IPv4 TAP protocol: 0x" << std::hex << tap_protocol << std::dec << std::endl;
            return;
        }

        // Parse IP header
        uint8_t version = (ip_packet[0] >> 4) & 0x0F;
        uint8_t ihl = ip_packet[0] & 0x0F;
        
        if (version != 4) {
            std::cerr << "Not an IPv4 packet (version=" << (int)version << ")" << std::endl;
            return;
        }

        if (ihl < 5) {
            std::cerr << "Invalid IP header length: " << (int)ihl << std::endl;
            return;
        }

        uint16_t total_length = (ip_packet[2] << 8) | ip_packet[3];
        uint8_t protocol = ip_packet[9];

        // Print packet details
        std::cout << "\n=== IPv4 Packet ===" << std::endl;
        std::cout << "TAP Protocol: 0x" << std::hex << tap_protocol << std::dec << std::endl;
        std::cout << "IP Header Length: " << (ihl * 4) << " bytes" << std::endl;
        std::cout << "Total Length: " << total_length << " bytes" << std::endl;
        
        // Print source and destination IP
        printf("Source IP: %d.%d.%d.%d\n",
               ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15]);
        printf("Dest IP: %d.%d.%d.%d\n",
               ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);

        std::cout << "Protocol: ";
        switch(protocol) {
            case 1:  std::cout << "ICMP"; break;
            case 6:  std::cout << "TCP"; break;
            case 17: std::cout << "UDP"; break;
            default: std::cout << "Unknown (" << (int)protocol << ")";
        }
        std::cout << std::endl;

        // Print first 64 bytes in hex (including TAP header)
        std::cout << "Packet Hex (including TAP header):" << std::endl;
        size_t dump_size = std::min(length, (size_t)64);
        for(size_t i = 0; i < dump_size; i++) {
            if(i % 16 == 0) std::cout << std::endl << std::hex << std::setw(4) << std::setfill('0') << i << ": ";
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)packet[i] << " ";
        }
        std::cout << std::dec << std::endl;  // Reset to decimal format

        // Write the packet back (including TAP header)
        write_packet(packet, length);
    }

public:
    WindowsTunInterface(const char* dev_name = "vpn0") : running(false) {
        if (!tun.start()) {
            throw std::runtime_error("Failed to create TUN device");
        }

        tun_handle = tun.getTunHandle();
        if (tun_handle == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("Invalid TUN handle");
        }

        if (!configure_tap_device()) {
            throw std::runtime_error("Failed to configure TAP device");
        }

        running = true;
        process_thread = std::thread(&WindowsTunInterface::process_packets, this);
    }

    ~WindowsTunInterface() {
        running = false;
        if (process_thread.joinable()) {
            process_thread.join();
        }
    }

    void process_packets() {
        std::vector<uint8_t> buffer(TAP_BUFFER_SIZE);
        OVERLAPPED overlapped = {0};
        overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

        while (running) {
            DWORD bytes_read;
            if (!ReadFile(tun_handle, buffer.data(), buffer.size(), &bytes_read, &overlapped)) {
                if (GetLastError() != ERROR_IO_PENDING) {
                    std::cerr << "ReadFile failed. Error: " << GetLastError() << std::endl;
                    break;
                }
            }

            if (WaitForSingleObject(overlapped.hEvent, INFINITE) != WAIT_OBJECT_0) {
                std::cerr << "WaitForSingleObject failed" << std::endl;
                break;
            }

            if (!GetOverlappedResult(tun_handle, &overlapped, &bytes_read, FALSE)) {
                std::cerr << "GetOverlappedResult failed" << std::endl;
                break;
            }

            ResetEvent(overlapped.hEvent);

            if (bytes_read > 0) {
                process_packet(buffer.data(), bytes_read);
            }
        }

        CloseHandle(overlapped.hEvent);
    }

    void start() {
        std::cout << "\nVirtual network interface is running." << std::endl;
        std::cout << "Interface IP: 10.0.0.1" << std::endl;
        std::cout << "Network: 10.0.0.0/24" << std::endl;
        std::cout << "Press Ctrl+C to stop." << std::endl << std::endl;
        
        while (running) {
            Sleep(1000);
        }
    }
};