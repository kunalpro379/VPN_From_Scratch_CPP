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

// Function to steal the packet, print it, and then allow it to continue
void stealAndPrintPacket(char *buffer, DWORD bytesRead)
{
     // Print the intercepted packet in hex format
     std::cout << "Intercepted packet:" << std::endl;
     printHexDump(buffer, bytesRead);

     // Modify the packet if needed
     // You can change the packet contents here if necessary

     // Continue transmitting the packet (write it back to the TAP device)
     // For now, this simply prints and continues; in a real use case, you might inject it
     // into the network stack or do further processing.
}

// Function to read packets from the TAP device
void interceptAndModifyPackets(HANDLE tapHandle)
{
     char buffer[BUFFER_SIZE];
     DWORD bytesRead;

     while (true)
     {
          std::cout << "Waiting for packets..." << std::endl;
          if (ReadFile(tapHandle, buffer, BUFFER_SIZE, &bytesRead, nullptr))
          {
               std::cout << "Intercepted " << bytesRead << " bytes from TAP device." << std::endl;

               // Steal the packet and print it
               stealAndPrintPacket(buffer, bytesRead);

               // Optionally: Inject the packet back into the network (not implemented in this example)
               // In a more complex implementation, you might want to inject the packet back into
               // the network stack or do something else with it.
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
