#include <windows.h>
#include <iostream>
#include <string>
#include <winioctl.h>
#include <vector>
#include <iomanip> // For hex printing
#include <cstring> // For memset

#pragma comment(lib, "ws2_32.lib")

#define TAP_DEVICE_GUID "{9848B1C0-704B-42D1-81AA-78947DBF323D}" // Replace this GUID with your actual TAP device GUID
#define BUFFER_SIZE 1500                                         // MTU size for buffer
#define TAP_WIN_IOCTL_SET_MEDIA_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAX_RETRIES 5 // Maximum retries before permanently discarding the packet

// Function to open the TAP device
HANDLE openTapDevice(const std::string &guid)
{
     std::string devicePath = "\\\\.\\Global\\" + guid + ".tap";
     HANDLE tapHandle = CreateFileA(
         devicePath.c_str(),
         GENERIC_READ | GENERIC_WRITE,
         0,
         nullptr,
         OPEN_EXISTING,
         FILE_ATTRIBUTE_SYSTEM,
         nullptr);

     if (tapHandle == INVALID_HANDLE_VALUE)
     {
          std::cerr << "Failed to open TAP device. Error: " << GetLastError() << std::endl;
          return nullptr;
     }

     std::cout << "Opened TAP device successfully." << std::endl;
     return tapHandle;
}

// Function to configure the TAP device (e.g., set it to 'connected' state)
void configureTapDevice(HANDLE tapHandle)
{
     DWORD len;
     ULONG status = TRUE;

     if (!DeviceIoControl(
             tapHandle,
             TAP_WIN_IOCTL_SET_MEDIA_STATUS,
             &status,
             sizeof(status),
             nullptr,
             0,
             &len,
             nullptr))
     {
          DWORD error = GetLastError();
          char errorMsg[256];
          FormatMessageA(
              FORMAT_MESSAGE_FROM_SYSTEM,
              NULL,
              error,
              MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
              errorMsg,
              sizeof(errorMsg),
              NULL);
          std::cerr << "Configuration failed. Error: " << error
                    << " - " << errorMsg << std::endl;
     }
}

// Function to calculate checksum
unsigned short checksum(void *buffer, int length)
{
     unsigned short *data = (unsigned short *)buffer;
     unsigned int sum = 0;
     unsigned short result;

     // Sum all 16-bit words
     while (length > 1)
     {
          sum += *data++;
          length -= 2;
     }

     // Add any leftover byte
     if (length == 1)
     {
          sum += *(unsigned char *)data;
     }

     // Fold 32-bit sum to 16 bits and return
     sum = (sum >> 16) + (sum & 0xFFFF);
     sum += (sum >> 16);
     result = ~sum;
     return result;
}

// Function to modify packets and recalculate checksums
void modifyPacketAndRecalculateChecksum(char *buffer, DWORD bytesRead)
{
     // Simulate packet modification: Modify the first byte of the IP packet
     buffer[0] = 0x01; // Example modification (change first byte)

     // Now, let's assume we are working with an IP + TCP packet:
     // We need to recalculate the IP checksum and the TCP checksum.

     // IP header starts from buffer[0], and its length is typically 20 bytes for IPv4
     unsigned short *ip_header = (unsigned short *)buffer;
     ip_header[5] = checksum((void *)ip_header, 20); // Recalculate IP checksum

     // TCP header starts after the IP header (assuming a standard 20-byte TCP header)
     unsigned short *tcp_header = (unsigned short *)(buffer + 20);
     tcp_header[5] = checksum((void *)tcp_header, 20); // Recalculate TCP checksum

     std::cout << "Packet modified and checksums recalculated!" << std::endl;
}

// Function to check if packet is discarded (e.g., invalid checksum)
bool isPacketDiscarded(char *buffer, DWORD bytesRead)
{
     unsigned short packetChecksum = checksum(buffer, bytesRead);
     // Simulate discard condition: discard packet if checksum is invalid
     if (packetChecksum != 0xFFFF) // This is an example, adjust logic as needed
     {
          return true;
     }
     return false;
}

// Function to visualize packet in hex format
void printHexDump(const char *buffer, DWORD bytesRead)
{
     for (DWORD i = 0; i < bytesRead; i++)
     {
          printf("%02X ", (unsigned char)buffer[i]);
          if ((i + 1) % 16 == 0) // New line after every 16 bytes
               std::cout << std::endl;
     }
     std::cout << std::endl;
}

// Function to read packets from the TAP device
void interceptAndModifyPackets(HANDLE tapHandle)
{
     char buffer[BUFFER_SIZE];
     DWORD bytesRead;

     int retryCount = 0;

     while (true)
     {
          std::cout << "Waiting for packets..." << std::endl;
          if (ReadFile(tapHandle, buffer, BUFFER_SIZE, &bytesRead, nullptr))
          {
               std::cout << "Intercepted " << bytesRead << " bytes from TAP device." << std::endl;

               // Print intercepted data in hex format for better readability
               std::cout << "Hex dump before modification:" << std::endl;
               printHexDump(buffer, bytesRead);

               // Check if the packet should be discarded
               if (isPacketDiscarded(buffer, bytesRead))
               {
                    std::cout << "Packet discarded due to checksum failure!" << std::endl;
                    retryCount++;

                    if (retryCount < MAX_RETRIES)
                    {
                         std::cout << "Retrying packet... (" << retryCount << "/" << MAX_RETRIES << ")" << std::endl;
                         // Retry by sending the same packet again (i.e., reprocess the same packet)
                         continue; // Skip further processing for this loop, retrying the packet
                    }
                    else
                    {
                         std::cout << "Max retries reached. Discarding packet permanently." << std::endl;
                         // Optionally, you could print the discarded packet in hex
                         std::cout << "Hex dump of discarded packet:" << std::endl;
                         printHexDump(buffer, bytesRead);
                         retryCount = 0; // Reset retry count after discarding
                         continue;
                    }
               }

               // Modify the packet and recalculate checksums
               modifyPacketAndRecalculateChecksum(buffer, bytesRead);

               // Print the modified packet in hex format
               std::cout << "Hex dump after modification:" << std::endl;
               printHexDump(buffer, bytesRead);

               // Optionally: Inject the modified packet back into the network (not implemented in this example)
          }
          else
          {
               DWORD error = GetLastError();
               if (error == ERROR_OPERATION_ABORTED)
               {
                    std::cerr << "Read operation aborted." << std::endl;
                    break;
               }
               std::cerr << "Failed to read from TAP device. Error: " << error << std::endl;
               break;
          }
     }
}

int main()
{
     // Open the TAP device with the provided GUID
     HANDLE tapHandle = openTapDevice(TAP_DEVICE_GUID);
     if (tapHandle != INVALID_HANDLE_VALUE)
     {
          // Configure the TAP device if it is successfully opened
          configureTapDevice(tapHandle);

          // Start intercepting, modifying, and printing packets
          interceptAndModifyPackets(tapHandle);

          // Close the TAP device when done
          CloseHandle(tapHandle);
     }

     return 0;
}
