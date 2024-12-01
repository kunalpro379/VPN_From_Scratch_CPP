#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <ctime>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Ws2_32.lib")

// Ethernet header
struct EthernetHeader {
    u_char dest[6];
    u_char source[6];
    u_short type;
};

// IP header
struct IpHeader {
    u_char ver_ihl;          // Version (4 bits) + Internet header length (4 bits)
    u_char tos;              // Type of service 
    u_short tlen;            // Total length 
    u_short identification;  // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char ttl;             // Time to live
    u_char proto;           // Protocol
    u_short crc;            // Header checksum
    struct in_addr saddr;   // Source address
    struct in_addr daddr;   // Destination address
};

// TCP header
struct TcpHeader {
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_int seq;             // Sequence number
    u_int ack;             // Acknowledgement number
    u_char data_offset;    // Data offset
    u_char flags;          // Flags
    u_short window;        // Window size
    u_short checksum;      // Checksum
    u_short urgent_ptr;    // Urgent pointer
};

void printMACAddress(const u_char* mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X", 
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void printPacketData(const u_char* data, int length) {
    std::cout << "\nPacket Data:" << std::endl;
    
    // Print as ASCII
    std::cout << "ASCII:" << std::endl;
    for (int i = 0; i < length; i++) {
        if (isprint(data[i]))
            std::cout << data[i];
        else
            std::cout << '.';
        if ((i + 1) % 80 == 0) std::cout << std::endl;
    }
    std::cout << std::endl;

    // Print as hex
    std::cout << "Hex dump:" << std::endl;
    for (int i = 0; i < length; i++) {
        if (i % 16 == 0) std::cout << "  ";
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) std::cout << std::endl;
    }
    std::cout << std::endl;
}

void packetHandler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    EthernetHeader* ethHeader = (EthernetHeader*)packet;
    if (ntohs(ethHeader->type) != 0x0800) // Not IP
        return;

    IpHeader* ipHeader = (IpHeader*)(packet + sizeof(EthernetHeader));
    int ipHeaderLen = (ipHeader->ver_ihl & 0xf) * 4;

    if (ipHeader->proto != IPPROTO_TCP) // Not TCP
        return;

    TcpHeader* tcpHeader = (TcpHeader*)(packet + sizeof(EthernetHeader) + ipHeaderLen);
    int tcpHeaderLen = (tcpHeader->data_offset >> 4) * 4;

    // Get source and destination ports
    u_short srcPort = ntohs(tcpHeader->sport);
    u_short dstPort = ntohs(tcpHeader->dport);

    // Only show HTTP/HTTPS traffic
    if ((srcPort != 80 && srcPort != 443 && dstPort != 80 && dstPort != 443))
        return;

    // Calculate payload offset and length
    int payloadOffset = sizeof(EthernetHeader) + ipHeaderLen + tcpHeaderLen;
    int payloadLen = pkthdr->len - payloadOffset;

    std::cout << "\n=== Intercepted Web Traffic ===" << std::endl;
    std::cout << "Time: " << ctime((const time_t*)&pkthdr->ts.tv_sec);
    
    std::cout << "MAC Addresses:" << std::endl;
    std::cout << "  Source: ";
    printMACAddress(ethHeader->source);
    std::cout << std::endl << "  Destination: ";
    printMACAddress(ethHeader->dest);
    std::cout << std::endl;

    std::cout << "IP Addresses:" << std::endl;
    std::cout << "  Source: " << inet_ntoa(ipHeader->saddr) << ":" << srcPort << std::endl;
    std::cout << "  Destination: " << inet_ntoa(ipHeader->daddr) << ":" << dstPort << std::endl;

    std::cout << "Packet Size: " << pkthdr->len << " bytes" << std::endl;
    std::cout << "Payload Size: " << payloadLen << " bytes" << std::endl;

    if (payloadLen > 0) {
        printPacketData(packet + payloadOffset, payloadLen);
    }

    std::cout << "=============================" << std::endl;
}

int main() {
    std::cout << "Starting Web Traffic Stealer..." << std::endl;
    std::cout << "WARNING: This program requires Npcap to be installed!" << std::endl;
    std::cout << "WARNING: Only use this for educational purposes!" << std::endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    
    // Get all network devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    // Print all devices
    std::cout << "\nAvailable Network Interfaces:" << std::endl;
    int i = 1;
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        std::cout << i++ << ". " << (d->description ? d->description : "No description") 
                  << " (" << d->name << ")" << std::endl;
    }

    // Select first device (usually the main network interface)
    pcap_if_t* device = alldevs;
    if (!device) {
        std::cerr << "No interfaces found!" << std::endl;
        return 1;
    }

    std::cout << "\nUsing interface: " << device->description << std::endl;

    // Open the device
    pcap_t* handle = pcap_open_live(
        device->name,    // device name
        65536,          // capture size
        1,              // promiscuous mode
        1000,           // read timeout
        errbuf          // error buffer
    );

    if (!handle) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Set filter to capture only TCP traffic
    struct bpf_program fp;
    char filter[] = "tcp";
    if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 1;
    }

    std::cout << "\nStarted capturing web traffic. Try browsing some websites!" << std::endl;
    std::cout << "Press Ctrl+C to stop." << std::endl;

    // Start capturing packets
    pcap_loop(handle, 0, packetHandler, nullptr);

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}
