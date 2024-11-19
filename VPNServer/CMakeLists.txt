# Minimum version of CMake required
cmake_minimum_required(VERSION 3.10)

# Set the project name and version
project(VPNServer VERSION 1.0)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add the source file
add_executable(VPNServer VPNServer.cpp)

# Link necessary libraries (for Windows, you need to link Winsock)
if(MSVC)
    target_link_libraries(VPNServer ws2_32)
endif()

