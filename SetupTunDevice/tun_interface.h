#ifndef TUN_INTERFACE_H
#define TUN_INTERFACE_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <winioctl.h>

#include <iostream>
#include <string>
#include <vector>
#include <thread>

// TAP-Windows device GUID
#define TAP_WINDOWS_GUID "tap0901"

// TAP IOCTLs
#define TAP_CONTROL_CODE(request,method) CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
#define TAP_IOCTL_GET_MAC               TAP_CONTROL_CODE(1, METHOD_BUFFERED)
#define TAP_IOCTL_GET_VERSION           TAP_CONTROL_CODE(2, METHOD_BUFFERED)
#define TAP_IOCTL_SET_MEDIA_STATUS      TAP_CONTROL_CODE(6, METHOD_BUFFERED)

class TunInterface {
private:
    HANDLE tunHandle;
    std::string devicePath;
    bool running;
    std::thread routingThread;

    // Original routing table backup
    PMIB_IPFORWARDTABLE originalRoutes;
    
    bool findTapDevice();
    bool backupRoutingTable();
    bool configureRoute();
    void restoreRoutingTable();
    void processPackets();

public:
    TunInterface();
    ~TunInterface();
    
    bool start();
    void stop();
    HANDLE getTunHandle() const { return tunHandle; }
};

#endif // TUN_INTERFACE_H