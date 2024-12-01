#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include <iomanip>
#include <ws2tcpip.h>
#include <vector>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")

// TAP-Windows definitions
#define TAP_WIN_IOCTL_SET_MEDIA_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Protocol numbers
#define PROTO_TCP 6
#define PROTO_UDP 17

// Ethernet header structure
struct EthernetHeader {
    unsigned char dest[6];
    unsigned char source[6];
    unsigned short type;
};

// IPv4 header structure
struct IPHeader {
    unsigned char  ihl:4;
    unsigned char  version:4;
    unsigned char  tos;
    unsigned short total_length;
    unsigned short id;
    unsigned short frag_off;
    unsigned char  ttl;
    unsigned char  protocol;
    unsigned short checksum;
    unsigned int   src_addr;
    unsigned int   dst_addr;
};

// TCP header structure
struct TCPHeader {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int   sequence;
    unsigned int   ack_sequence;
    unsigned char  data_offset:4;
    unsigned char  reserved:4;
    unsigned char  flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_ptr;
};

// UDP header structure
struct UDPHeader {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned short length;
    unsigned short checksum;
};

class PacketInterceptor {
private:
    HANDLE tapHandle;
    static const int BUFFER_SIZE = 65535;

    void printMACAddress(const unsigned char* mac) {
        for (int i = 0; i < 6; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << static_cast<int>(mac[i]);
            if (i < 5) std::cout << ":";
        }
        std::cout << std::dec;
    }

    void printIPAddress(unsigned int ip) {
        unsigned char bytes[4];
        bytes[0] = ip & 0xFF;
        bytes[1] = (ip >> 8) & 0xFF;
        bytes[2] = (ip >> 16) & 0xFF;
        bytes[3] = (ip >> 24) & 0xFF;
        std::cout << static_cast<int>(bytes[3]) << "."
                  << static_cast<int>(bytes[2]) << "."
                  << static_cast<int>(bytes[1]) << "."
                  << static_cast<int>(bytes[0]);
    }

    void analyzePacket(const char* buffer, int length) {
        if (length < sizeof(EthernetHeader)) {
            return;
        }

        const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(buffer);
        
        std::cout << "\n=== Packet Details ===" << std::endl;
        std::cout << "Ethernet Header:" << std::endl;
        std::cout << "  Destination MAC: ";
        printMACAddress(eth->dest);
        std::cout << "\n  Source MAC: ";
        printMACAddress(eth->source);
        std::cout << std::endl;

        // Check if it's an IP packet (0x0800 is IP)
        if (ntohs(eth->type) == 0x0800) {
            const IPHeader* ip = reinterpret_cast<const IPHeader*>(buffer + sizeof(EthernetHeader));
            
            std::cout << "IP Header:" << std::endl;
            std::cout << "  Source IP: ";
            printIPAddress(ip->src_addr);
            std::cout << "\n  Destination IP: ";
            printIPAddress(ip->dst_addr);
            std::cout << "\n  Protocol: ";

            if (ip->protocol == PROTO_TCP) {
                const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(buffer + sizeof(EthernetHeader) + (ip->ihl * 4));
                std::cout << "TCP" << std::endl;
                std::cout << "  Source Port: " << ntohs(tcp->src_port) << std::endl;
                std::cout << "  Destination Port: " << ntohs(tcp->dst_port) << std::endl;
            }
            else if (ip->protocol == PROTO_UDP) {
                const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(buffer + sizeof(EthernetHeader) + (ip->ihl * 4));
                std::cout << "UDP" << std::endl;
                std::cout << "  Source Port: " << ntohs(udp->src_port) << std::endl;
                std::cout << "  Destination Port: " << ntohs(udp->dst_port) << std::endl;
            }
            else {
                std::cout << "Other (" << static_cast<int>(ip->protocol) << ")" << std::endl;
            }
        }
        std::cout << "===================" << std::endl;
    }

public:
    PacketInterceptor() : tapHandle(INVALID_HANDLE_VALUE) {}

    bool start(const std::string& tapGuid) {
        // Initialize Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "Failed to initialize Winsock" << std::endl;
            return false;
        }

        std::string devicePath = "\\\\.\\Global\\" + tapGuid + ".tap";
        std::cout << "Opening TAP device: " << devicePath << std::endl;
        
        tapHandle = CreateFileA(
            devicePath.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_SYSTEM,  
            nullptr
        );

        if (tapHandle == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            std::cerr << "Failed to open TAP device. Error code: " << error << std::endl;
            switch(error) {
                case ERROR_FILE_NOT_FOUND:
                    std::cerr << "TAP device not found. Make sure TAP driver is installed." << std::endl;
                    break;
                case ERROR_ACCESS_DENIED:
                    std::cerr << "Access denied. Try running as administrator." << std::endl;
                    break;
                default:
                    std::cerr << "Unknown error occurred." << std::endl;
            }
            return false;
        }

        std::cout << "TAP device opened successfully" << std::endl;

        // Set TAP interface status to connected
        DWORD len;
        ULONG status = 1;
        if (!DeviceIoControl(tapHandle, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
            &status, sizeof(status),
            &status, sizeof(status),
            &len, nullptr))
        {
            DWORD error = GetLastError();
            std::cerr << "Failed to set TAP interface status. Error: " << error << std::endl;
            CloseHandle(tapHandle);
            return false;
        }

        std::cout << "TAP interface status set to connected" << std::endl;
        return true;
    }

    void interceptPackets() {
        char buffer[BUFFER_SIZE];
        DWORD bytesRead;

        std::cout << "Starting packet interception..." << std::endl;

        while (true) {
            if (ReadFile(tapHandle, buffer, BUFFER_SIZE, &bytesRead, nullptr)) {
                if (bytesRead > 0) {
                    std::cout << "\nIntercepted packet of " << bytesRead << " bytes" << std::endl;
                    analyzePacket(buffer, bytesRead);
                }
            }
            else {
                DWORD error = GetLastError();
                std::cerr << "Failed to read from TAP device. Error code: " << error << std::endl;
                switch(error) {
                    case ERROR_INVALID_HANDLE:
                        std::cerr << "Invalid handle. TAP device might be disconnected." << std::endl;
                        break;
                    case ERROR_INVALID_PARAMETER:
                        std::cerr << "Invalid parameter in ReadFile." << std::endl;
                        break;
                    default:
                        std::cerr << "Unknown error occurred while reading." << std::endl;
                }
                break;
            }
        }
    }

    ~PacketInterceptor() {
        if (tapHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(tapHandle);
        }
    }
};

int main() {
    std::cout << "Starting packet interceptor..." << std::endl;
    
    PacketInterceptor interceptor;
    if (interceptor.start("{9848B1C0-704B-42D1-81AA-78947DBF323D}")) {
        std::cout << "Network interface started. Press Ctrl+C to stop..." << std::endl;
        interceptor.interceptPackets();
    } else {
        std::cerr << "Failed to start network interface" << std::endl;
        return 1;
    }
    return 0;
}
