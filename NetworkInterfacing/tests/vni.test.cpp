#include "tun.cpp"
#include <csignal>

WindowsTunInterface* g_interface = nullptr;

void signal_handler(int signal) {
    if (g_interface) {
        g_interface->~WindowsTunInterface();
        g_interface = nullptr;
    }
    exit(0);
}

int main() {
    signal(SIGINT, signal_handler);
    
    try {
        g_interface = new WindowsTunInterface("vpn0");
        g_interface->start();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}