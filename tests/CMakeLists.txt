cmake_minimum_required(VERSION 3.10) # Minimum version of CMake, adjust as needed
project(VPNServerProject) # Replace this with your project name

# Set the C++ standard to C++17 (or whichever version you prefer)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include the "Include" directory for header files
include_directories(${CMAKE_SOURCE_DIR}/Include)
cmake .. -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake

# Add the main.cpp file as the executable target
add_executable(vpn_server main.cpp)

# If there are additional source files (like VPNServer.cpp), add them here
# Example: add_executable(vpn_server main.cpp VPNServer.cpp)
