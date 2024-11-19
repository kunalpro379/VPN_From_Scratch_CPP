#include <windows.h>
#include <iostream>
#include <string>
#include <winioctl.h>
#include <vector>

#define TAP_DEVICE_GUID "{9848B1C0-704B-42D1-81AA-78947DBF323D}"
#define TAP_WIN_IOCTL_SET_MEDIA_STATUS (CTL_CODE(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS))

// Function to open the TAP device by its GUID
HANDLE openTapDevice(const std::string &guid)
{
     std::string devicePath = "\\\\.\\Global\\" + guid + ".tap";
     HANDLE tapHandle = CreateFileA(
         devicePath.c_str(),
         GENERIC_READ | GENERIC_WRITE,
         0,
         nullptr,
         OPEN_EXISTING,
         FILE_ATTRIBUTE_SYSTEM, // Remove FILE_FLAG_OVERLAPPED if not needed
         nullptr);

     if (tapHandle == INVALID_HANDLE_VALUE)
     {
          std::cerr << "Failed to open TAP device: " << GetLastError() << std::endl;
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
     // Set the TAP adapter status to 'connected'
     if (!DeviceIoControl(
             tapHandle,
             TAP_WIN_IOCTL_SET_MEDIA_STATUS,
             &status,
             sizeof(status),
             &status,
             sizeof(status),
             &len,
             nullptr))
     {
          std::cerr << "Failed to configure TAP device: " << GetLastError() << std::endl;
     }
     else
     {
          std::cout << "TAP device configured successfully." << std::endl;
     }
}

// Function to read a packet from the TAP device
int readPacketFromTap(HANDLE tapHandle, char *buffer, size_t bufferSize)
{
     DWORD bytesRead;
     if (ReadFile(tapHandle, buffer, static_cast<DWORD>(bufferSize), &bytesRead, nullptr))
     {
          std::cout << "Read " << bytesRead << " bytes from TAP device." << std::endl;
          return bytesRead;
     }
     else
     {
          DWORD error = GetLastError();
          std::cerr << "Failed to read from TAP device. Error code: " << error << std::endl;
          return -1;
     }
}

// Function to write a packet to the TAP device
int writePacketToTap(HANDLE tapHandle, const char *buffer, size_t bufferSize)
{
     DWORD bytesWritten;
     if (WriteFile(tapHandle, buffer, static_cast<DWORD>(bufferSize), &bytesWritten, nullptr))
     {
          std::cout << "Wrote " << bytesWritten << " bytes to TAP device." << std::endl;
          return bytesWritten;
     }
     else
     {
          DWORD error = GetLastError();
          std::cerr << "Failed to write to TAP device. Error code: " << error << std::endl;
          return -1;
     }
}

int main()
{
     std::string tapGuid = TAP_DEVICE_GUID;

     // Open the TAP device
     HANDLE tapHandle = openTapDevice(tapGuid);

     if (tapHandle != nullptr)
     {
          // Configure the TAP device
          configureTapDevice(tapHandle);

          // Example of reading from the TAP device
          char readBuffer[1500]; // typical MTU size
          int bytesRead = readPacketFromTap(tapHandle, readBuffer, sizeof(readBuffer));
          if (bytesRead > 0)
          {
               // Process the data (e.g., print or analyze)
               std::cout << "Processing the data read from TAP..." << std::endl;
          }

          // Example of writing to the TAP device
          const char *writeData = "Hello, TAP device!";
          int bytesWritten = writePacketToTap(tapHandle, writeData, strlen(writeData));
          if (bytesWritten > 0)
          {
               std::cout << "Sent data to TAP device!" << std::endl;
          }

          // Close the TAP device handle
          CloseHandle(tapHandle);
     }

     return 0;
}
