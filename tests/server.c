#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>  // For inet_ntop and INET_ADDRSTRLEN
#include <windows.h>
#include <io.h>        // For _access
#include <sys/stat.h>  // For stat
#include <direct.h>

// OpenSSL includes
#include <openssl/applink.c>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define BUFF_SIZE 2000
#define SERVER_PORT 4433

// TAP-Windows adapter constants
#define TAP_WIN_IOCTL(nr) CTL_CODE(FILE_DEVICE_UNKNOWN, nr, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TAP_WIN_CONTROL_CODE(request,method) \
  CTL_CODE (FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
#define TAP_IOCTL_GET_MAC               TAP_WIN_IOCTL(1)
#define TAP_IOCTL_GET_VERSION           TAP_WIN_IOCTL(2)
#define TAP_IOCTL_GET_MTU               TAP_WIN_IOCTL(3)
#define TAP_IOCTL_GET_INFO              TAP_WIN_IOCTL(4)
#define TAP_IOCTL_CONFIG_POINT_TO_POINT TAP_WIN_IOCTL(5)
#define TAP_IOCTL_SET_MEDIA_STATUS      TAP_WIN_IOCTL(6)
#define TAP_IOCTL_CONFIG_DHCP_MASQ      TAP_WIN_IOCTL(7)
#define TAP_IOCTL_GET_LOG_LINE          TAP_WIN_IOCTL(8)
#define TAP_IOCTL_CONFIG_DHCP_SET_OPT   TAP_WIN_IOCTL(9)
#define TAP_IOCTL_CONFIG_TUN            TAP_WIN_IOCTL(10)

// Network adapter GUIDs
#define ADAPTER_KEY "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define NETWORK_CONNECTIONS_KEY "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

// Function to list all network adapters
void list_network_adapters() {
    HKEY adapter_key;
    DWORD len;
    printf("\nChecking network adapters:\n");
    printf("---------------------------\n");
    
    long status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0, KEY_READ, &adapter_key);
    if (status != ERROR_SUCCESS) {
        printf("Error opening registry key: %ld\n", status);
        return;
    }

    char enum_name[256];
    DWORD i = 0;
    DWORD enum_len = sizeof(enum_name);

    while (RegEnumKeyExA(adapter_key, i, enum_name, &enum_len, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        HKEY unit_key;
        char unit_path[512];
        snprintf(unit_path, sizeof(unit_path), "%s\\%s", ADAPTER_KEY, enum_name);

        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, unit_path, 0, KEY_READ, &unit_key) == ERROR_SUCCESS) {
            char component_id[256] = {0};
            char driver_desc[256] = {0};
            char net_cfg_instance_id[256] = {0};
            DWORD len = sizeof(component_id);
            
            // Get ComponentId
            RegQueryValueExA(unit_key, "ComponentId", NULL, NULL, (LPBYTE)component_id, &len);
            
            // Get DriverDesc
            len = sizeof(driver_desc);
            RegQueryValueExA(unit_key, "DriverDesc", NULL, NULL, (LPBYTE)driver_desc, &len);
            
            // Get NetCfgInstanceId
            len = sizeof(net_cfg_instance_id);
            RegQueryValueExA(unit_key, "NetCfgInstanceId", NULL, NULL, (LPBYTE)net_cfg_instance_id, &len);
            
            if (strlen(component_id) > 0 && strlen(driver_desc) > 0) {
                printf("Adapter %d:\n", i);
                printf("  Description: %s\n", driver_desc);
                printf("  Component ID: %s\n", component_id);
                printf("  Instance ID: %s\n", net_cfg_instance_id);
                if (strncmp(component_id, "tap0901", 7) == 0 || 
                    strncmp(component_id, "tap0801", 7) == 0 ||
                    strstr(driver_desc, "TAP-Windows") != NULL ||
                    strstr(driver_desc, "OpenVPN") != NULL) {
                    printf("  ** This is a TAP adapter **\n");
                }
                printf("\n");
            }
            RegCloseKey(unit_key);
        }
        i++;
        enum_len = sizeof(enum_name);
    }
    RegCloseKey(adapter_key);
}

// Function to find TAP adapter GUID
char* find_tap_guid() {
    HKEY adapter_key;
    DWORD len;
    char *guid = NULL;
    
    printf("\nLooking for TAP adapter...\n");
    printf("---------------------------\n");
    
    long status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0, KEY_READ, &adapter_key);
    if (status != ERROR_SUCCESS) {
        printf("Error opening registry key: %ld\n", status);
        return NULL;
    }

    char enum_name[256];
    DWORD i = 0;
    DWORD enum_len = sizeof(enum_name);

    while (RegEnumKeyExA(adapter_key, i, enum_name, &enum_len, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        HKEY unit_key;
        char unit_path[512];
        snprintf(unit_path, sizeof(unit_path), "%s\\%s", ADAPTER_KEY, enum_name);

        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, unit_path, 0, KEY_READ, &unit_key) == ERROR_SUCCESS) {
            char component_id[256] = {0};
            char driver_desc[256] = {0};
            len = sizeof(component_id);
            
            if (RegQueryValueExA(unit_key, "ComponentId", NULL, NULL, (LPBYTE)component_id, &len) == ERROR_SUCCESS) {
                // Get DriverDesc for additional info
                len = sizeof(driver_desc);
                RegQueryValueExA(unit_key, "DriverDesc", NULL, NULL, (LPBYTE)driver_desc, &len);
                
                if (strncmp(component_id, "tap0901", 7) == 0 || 
                    strncmp(component_id, "tap0801", 7) == 0 ||
                    strstr(driver_desc, "TAP-Windows") != NULL ||
                    strstr(driver_desc, "OpenVPN") != NULL) {
                    char net_cfg_instance_id[256];
                    len = sizeof(net_cfg_instance_id);
                    
                    if (RegQueryValueExA(unit_key, "NetCfgInstanceId", NULL, NULL, (LPBYTE)net_cfg_instance_id, &len) == ERROR_SUCCESS) {
                        printf("Found TAP adapter:\n");
                        printf("  Description: %s\n", driver_desc);
                        printf("  Component ID: %s\n", component_id);
                        printf("  Instance ID: %s\n", net_cfg_instance_id);
                        guid = _strdup(net_cfg_instance_id);
                        RegCloseKey(unit_key);
                        break;
                    }
                }
            }
            RegCloseKey(unit_key);
        }
        i++;
        enum_len = sizeof(enum_name);
    }
    
    RegCloseKey(adapter_key);
    
    if (guid == NULL) {
        printf("\nNo TAP adapter found. Available network adapters:\n");
        list_network_adapters();
    }
    
    return guid;
}

// Message header for TLS communications
struct tls_header {
    uint16_t tlsh_len;  // Length of the data
    uint8_t  tlsh_type; // Type of the message
};

// Credential header for login
struct cred_header {
    uint16_t user_len;  // Length of username
    uint16_t pwd_len;   // Length of password
};

HANDLE OpenTap(char *devicename) {
    char *guid;
    HANDLE handle;
    char device_path[512];

    // Check if running as Administrator
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    
    if (AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &AdministratorsGroup)) {
        CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin);
        FreeSid(AdministratorsGroup);
    }

    if (!isAdmin) {
        printf("\nError: This program must be run as Administrator!\n");
        printf("Please right-click the executable and select 'Run as administrator'\n\n");
        return INVALID_HANDLE_VALUE;
    }

    // Find the TAP device GUID
    guid = find_tap_guid();
    if (guid == NULL) {
        printf("\nError: No TAP-Windows adapters found.\n");
        printf("Please install OpenVPN or TAP-Windows driver from:\n");
        printf("https://openvpn.net/community-downloads/\n\n");
        return INVALID_HANDLE_VALUE;
    }

    // Create TAP device path
    snprintf(device_path, sizeof(device_path), "\\\\.\\Global\\%s.tap", guid);
    printf("Opening TAP device: %s\n", device_path);

    // Attempt to open the TAP device
    handle = CreateFileA(device_path,
                        GENERIC_READ | GENERIC_WRITE,
                        0,
                        0,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
                        0);

    if (handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        printf("\nError: Could not open TAP device (Error: %lu)\n", error);
        
        switch(error) {
            case ERROR_ACCESS_DENIED:
                printf("Access denied. Please make sure:\n");
                printf("1. You are running as Administrator\n");
                printf("2. The TAP adapter is not in use by another program\n");
                break;
            case ERROR_FILE_NOT_FOUND:
                printf("TAP device not found. Please:\n");
                printf("1. Install OpenVPN or TAP-Windows driver\n");
                printf("2. Check if the TAP adapter is enabled in Network Connections\n");
                break;
            case ERROR_SHARING_VIOLATION:
                printf("TAP device is already in use by another program.\n");
                printf("Please close any VPN applications that might be using it.\n");
                break;
            default:
                printf("Unknown error occurred. Please make sure TAP-Windows is properly installed.\n");
        }
        printf("\nTroubleshooting steps:\n");
        printf("1. Open Network Connections (Win+R, ncpa.cpl)\n");
        printf("2. Look for 'TAP-Windows Adapter V9'\n");
        printf("3. If not found, install OpenVPN from https://openvpn.net/community-downloads/\n");
        printf("4. If found but disabled, right-click and enable it\n");
        printf("5. Try running the program again as Administrator\n\n");
    } else {
        printf("Successfully opened TAP device\n");
    }

    free(guid);
    return handle;
}

HANDLE createTunDevice() {
    // Check if running as Administrator
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    HANDLE handle;  // Declare handle at the start
    
    if (AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &AdministratorsGroup)) {
        CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin);
        FreeSid(AdministratorsGroup);
    }

    if (!isAdmin) {
        printf("\nError: This program must be run as Administrator!\n");
        printf("Please right-click the executable and select 'Run as administrator'\n\n");
        return INVALID_HANDLE_VALUE;
    }

    char *guid = find_tap_guid();
    if (guid == NULL) {
        printf("\nError: No TAP-Windows adapters found.\n");
        printf("Please install OpenVPN or TAP-Windows driver from:\n");
        printf("https://openvpn.net/community-downloads/\n\n");
        return INVALID_HANDLE_VALUE;
    }

    // Try to stop the TAP adapter first
    char device_path[512];
    snprintf(device_path, sizeof(device_path), "\\\\.\\Global\\%s.tap", guid);
    printf("Opening TAP device: %s\n", device_path);

    handle = CreateFileA(device_path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_SYSTEM, // Remove FILE_FLAG_OVERLAPPED
        NULL);

    if (handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        printf("\nError: Could not open TAP device (Error: %lu)\n", error);
        
        // Try to reset the TAP adapter
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "netsh interface set interface \"TAP-Windows Adapter V9\" admin=disable");
        system(cmd);
        Sleep(1000); // Wait for the command to take effect
        snprintf(cmd, sizeof(cmd), "netsh interface set interface \"TAP-Windows Adapter V9\" admin=enable");
        system(cmd);
        Sleep(1000); // Wait for the adapter to come back up

        // Try opening again
        handle = CreateFileA(device_path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_SYSTEM, // Remove FILE_FLAG_OVERLAPPED
            NULL);

        if (handle == INVALID_HANDLE_VALUE) {
            error = GetLastError();
            printf("Still could not open TAP device after reset (Error: %lu)\n", error);
            printf("\nTroubleshooting steps:\n");
            printf("1. Open Device Manager\n");
            printf("2. Find 'TAP-Windows Adapter V9' under Network Adapters\n");
            printf("3. Right-click and select 'Disable device'\n");
            printf("4. Wait a few seconds, then right-click and select 'Enable device'\n");
            printf("5. If that doesn't work, try uninstalling and reinstalling OpenVPN\n\n");
            free(guid);
            return INVALID_HANDLE_VALUE;
        }
    }

    // Set TAP adapter to connected state
    ULONG status = TRUE;
    DWORD len;
    if (!DeviceIoControl(handle, TAP_IOCTL_SET_MEDIA_STATUS,
        &status, sizeof(status), &status, sizeof(status), &len, NULL)) {
        printf("\nError: Could not set TAP adapter status\n");
        printf("Please make sure the TAP adapter is properly installed and enabled.\n");
        CloseHandle(handle);
        free(guid);
        return INVALID_HANDLE_VALUE;
    }

    // Configure TAP interface
    ULONG ip_addr = htonl(0x0A0A0A01);  // 10.10.10.1
    ULONG subnet_mask = htonl(0xFFFFFF00);  // 255.255.255.0
    ULONG network = ip_addr & subnet_mask;
    UCHAR config[12];
    memcpy(&config[0], &ip_addr, 4);
    memcpy(&config[4], &network, 4);
    memcpy(&config[8], &subnet_mask, 4);

    if (!DeviceIoControl(handle, TAP_IOCTL_CONFIG_TUN,
        config, sizeof(config), config, sizeof(config), &len, NULL)) {
        printf("\nError: Could not configure TAP adapter network settings\n");
        CloseHandle(handle);
        free(guid);
        return INVALID_HANDLE_VALUE;
    }

    printf("Successfully opened and configured TAP device\n");
    printf("TAP adapter IP: 10.10.10.1/24\n");
    free(guid);
    return handle;
}
// void tunSelected(HANDLE tunfd, SSL* ssl) {
//     int length, err;
//     unsigned char buff[BUFF_SIZE];
//     char buffer[4];
//     DWORD bytesRead;
    
//     memset(buffer, 0, 4);
//     struct tls_header *tls = (struct tls_header *)buffer;
//     printf("Got a packet from TUN\n");
    
//     memset(buff, 0, BUFF_SIZE);
//     if (ReadFile(tunfd, buff, BUFF_SIZE, &bytesRead, NULL)) {
//         length = (int)bytesRead;
//         tls->tlsh_len = htons(length);
//         err = SSL_write(ssl, tls, sizeof(struct tls_header)); CHK_SSL(err);
//         err = SSL_write(ssl, buff, length); CHK_SSL(err);
//     }
// }
void tunSelected(HANDLE tunfd, SSL* ssl) {
    int length, err;
    unsigned char buff[BUFF_SIZE];
    char buffer[4];
    DWORD bytesRead;
    
    memset(buffer, 0, 4);
    struct tls_header *tls = (struct tls_header *)buffer;
    printf("Got a packet from TUN\n");
    
    memset(buff, 0, BUFF_SIZE);
    if (ReadFile(tunfd, buff, BUFF_SIZE, &bytesRead, NULL)) {
        length = (int)bytesRead;
        tls->tlsh_len = htons(length);
        err = SSL_write(ssl, tls, sizeof(struct tls_header));
        if (err <= 0) {
            printf("Error sending TLS header\n");
            return;
        }
        err = SSL_write(ssl, buff, length);
        if (err <= 0) {
            printf("Error sending data\n");
            return;
        }
    }
}
void socketSelected(int sockfd, SSL* ssl, HANDLE tunfd) {
    int len, data_length, length, err, total;
    unsigned char buff[BUFF_SIZE];
    DWORD written;
    
    memset(buff, 0, BUFF_SIZE);
    char buffer[4];
    memset(buffer, 0, 4);
    struct tls_header *tls = (struct tls_header *)buffer;
    
    printf("Got a packet from the tunnel\n");
    err = SSL_read(ssl, tls, sizeof(struct tls_header)); 
    if (err <= 0) {
        printf("Error reading TLS header\n");
        return;
    }
    
    data_length = tls->tlsh_len;
    length = ntohs(data_length);
    if (length > BUFF_SIZE) {
        printf("Packet too large: %d\n", length);
        return;
    }
    total = length;
    
    unsigned char *ptr = buff;
    do {
        len = SSL_read(ssl, ptr, length);
        if (len <= 0) {
            printf("Error reading data from tunnel\n");
            return;
        }
        ptr += len;
        length -= len;
    } while (length > 0);
    
    if (!WriteFile(tunfd, buff, total, &written, NULL)) {
        DWORD error = GetLastError();
        printf("Error writing to TUN device (Error: %lu)\n", error);
        switch(error) {
            case ERROR_ACCESS_DENIED:
                printf("Access denied. Check TAP device permissions.\n");
                break;
            case ERROR_INVALID_HANDLE:
                printf("Invalid TAP device handle.\n");
                break;
            case ERROR_NOT_ENOUGH_MEMORY:
                printf("Not enough memory to write data.\n");
                break;
            default:
                printf("Unknown error occurred.\n");
        }
        return;
    }
    printf("Successfully wrote %lu bytes to TUN\n", written);
}
int setupTCPServer(int port) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed with error: %d\n", WSAGetLastError());
        return -1;
    }

    struct sockaddr_in sa_server;
    int listen_sock;
    listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        printf("Socket creation failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return -1;
    }
    
    // Enable socket reuse to avoid "address already in use" errors
    int opt = 1;
    if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0) {
        printf("setsockopt(SO_REUSEADDR) failed with error: %d\n", WSAGetLastError());
        closesocket(listen_sock);
        WSACleanup();
        return -1;
    }
    
    memset(&sa_server, 0, sizeof(sa_server));
    sa_server.sin_family = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port = htons(port);
    
    printf("Binding to port %d...\n", port);
    int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
    if (err == SOCKET_ERROR) {
        printf("Bind failed with error: %d\n", WSAGetLastError());
        printf("Make sure no other process is using port %d\n", port);
        closesocket(listen_sock);
        WSACleanup();
        return -1;
    }
    printf("Successfully bound to port %d\n", port);
    
    printf("Starting to listen...\n");
    err = listen(listen_sock, 5);
    if (err == SOCKET_ERROR) {
        printf("Listen failed with error: %d\n", WSAGetLastError());
        closesocket(listen_sock);
        WSACleanup();
        return -1;
    }
    printf("Server is now listening for connections\n");
    
    return listen_sock;
}

void reply_to_client(SSL *ssl, int result) {
    int err;
    char buff[10];
    memset(buff, 0, 10);
    
    char buffer[4];
    memset(buffer, 0, 4);
    struct tls_header *tls = (struct tls_header *)buffer;
    buff[0] = result;
    
    tls->tlsh_len = htons(strlen(buff));
    err = SSL_write(ssl, tls, sizeof(struct tls_header)); CHK_SSL(err);
    err = SSL_write(ssl, buff, strlen(buff)); CHK_SSL(err);
}

int login_verification(SSL *ssl) {
    // Simple password verification for Windows
    // In a real application, you would use Windows authentication APIs
    const char *valid_user = "unal";
    const char *valid_pass = "kanua";
    
    int len, data_length, length, err;
    char buffered[5000];
    memset(buffered, 0, 5000);
    struct cred_header *cred = (struct cred_header *)buffered;
    
    char buffer[4];
    memset(buffer, 0, 4);
    struct tls_header *tls = (struct tls_header *)buffer;
    
    printf("Received credentials. Verifying now.\n");
    err = SSL_read(ssl, tls, sizeof(struct tls_header)); 
    if (err <= 0) {
        printf("Error reading TLS header\n");
        return -1;
    }
    
    data_length = tls->tlsh_len;
    length = ntohs(data_length);
    printf("Credential data length: %d\n", length);
    
    // Read the credential data
    int total_read = 0;
    while (total_read < length) {
        len = SSL_read(ssl, buffered + total_read, length - total_read);
        if (len <= 0) {
            printf("Error reading credential data\n");
            return -1;
        }
        total_read += len;
    }
    
    cred = (struct cred_header *)buffered;
    int user_len = ntohs(cred->user_len);
    int passwd_len = ntohs(cred->pwd_len);
    printf("Username length: %d, Password length: %d\n", user_len, passwd_len);
    
    char user[256] = {0};
    char pwd[256] = {0};
    char *data = buffered + sizeof(struct cred_header);
    
    strncpy(user, data, user_len);
    data += user_len;
    strncpy(pwd, data, passwd_len);
    
    printf("Received username: '%s'\n", user);
    printf("Received password: '%s'\n", pwd);
    printf("Expected username: '%s'\n", valid_user);
    printf("Expected password: '%s'\n", valid_pass);
    
    if (strcmp(user, valid_user) == 0 && strcmp(pwd, valid_pass) == 0) {
        printf("Login successful!\n");
        reply_to_client(ssl, 1);
        return 1;
    }
    
    printf("Login failed: Invalid credentials\n");
    reply_to_client(ssl, -1);
    return -1;
}

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
    if (!preverify_ok) {
        X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
        int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
        int err = X509_STORE_CTX_get_error(x509_ctx);
        
        char subject[256];
        X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
        
        printf("Certificate verification error at depth: %d\n", depth);
        printf("  Subject: %s\n", subject);
        printf("  Error %d: %s\n", err, X509_verify_cert_error_string(err));
        
        // Accept the certificate despite verification failure (for debugging)
        return 1;
    }
    return preverify_ok;
}

SSL_CTX* setupTLSServer(void) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Set minimum TLS version
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Set cipher list to secure ciphers
    if (!SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5:!RC4")) {
        printf("Error setting cipher list\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Set certificate verification paths
    if (!SSL_CTX_load_verify_locations(ctx, "./certs/ca-cert.pem", NULL)) {
        printf("Error loading CA certificate\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Load server certificate and private key
    if (!SSL_CTX_use_certificate_file(ctx, "./certs/server-cert.pem", SSL_FILETYPE_PEM)) {
        printf("Error loading server certificate\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (!SSL_CTX_use_PrivateKey_file(ctx, "./certs/server-key.pem", SSL_FILETYPE_PEM)) {
        printf("Error loading server private key\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Verify private key
    if (!SSL_CTX_check_private_key(ctx)) {
        printf("Private key does not match the certificate\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Set verification mode
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
    SSL_CTX_set_verify_depth(ctx, 4);

    return ctx;
}

// Function to generate a key pair
EVP_PKEY* generate_key() {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    // Create a context for key generation
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        goto cleanup;
    }

    // Initialize the key generation
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        goto cleanup;
    }

    // Set the RSA key bits
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        goto cleanup;
    }

    // Generate the key
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        goto cleanup;
    }

cleanup:
    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    return pkey;
}

// Function to generate a self-signed CA certificate
X509* generate_ca_certificate(EVP_PKEY *ca_key) {
    X509 *ca_cert = X509_new();
    X509_NAME *name = X509_NAME_new();

    // Set certificate details
    X509_set_version(ca_cert, 2);  // X509v3
    ASN1_INTEGER_set(X509_get_serialNumber(ca_cert), 1);
    X509_gmtime_adj(X509_get_notBefore(ca_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(ca_cert), 31536000L); // Valid for 1 year

    // Set CA certificate subject/issuer
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"VPN CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"VPN Root CA", -1, -1, 0);

    X509_set_subject_name(ca_cert, name);
    X509_set_issuer_name(ca_cert, name);
    X509_set_pubkey(ca_cert, ca_key);

    // Add CA basic constraints
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ca_cert, ca_cert, NULL, NULL, 0);

    X509_EXTENSION *ext;
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "critical,CA:TRUE,pathlen:0");
    X509_add_ext(ca_cert, ext, -1);
    X509_EXTENSION_free(ext);

    // Add key usage
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, "critical,keyCertSign,cRLSign");
    X509_add_ext(ca_cert, ext, -1);
    X509_EXTENSION_free(ext);

    // Add subject key identifier
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
    X509_add_ext(ca_cert, ext, -1);
    X509_EXTENSION_free(ext);

    // Self-sign the CA certificate
    if (!X509_sign(ca_cert, ca_key, EVP_sha256())) {
        X509_free(ca_cert);
        return NULL;
    }

    X509_NAME_free(name);
    return ca_cert;
}

// Function to generate a server/client certificate signed by CA
X509* generate_certificate(EVP_PKEY *key, X509 *ca_cert, EVP_PKEY *ca_key, const char *cn, int is_server) {
    X509 *cert = X509_new();
    X509_NAME *name = X509_NAME_new();

    // Set certificate details
    X509_set_version(cert, 2);  // X509v3
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 2);  // Different serial from CA
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);  // Valid for 1 year

    // Set certificate subject
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"VPN", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)cn, -1, -1, 0);

    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));  // Issuer is CA's subject
    X509_set_pubkey(cert, key);

    // Add extensions
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ca_cert, cert, NULL, NULL, 0);

    // Basic constraints - not a CA
    X509_EXTENSION *ext;
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "critical,CA:FALSE");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    // Key usage
    const char *key_usage = is_server ? 
        "critical,digitalSignature,keyEncipherment,keyAgreement" :
        "critical,digitalSignature,keyEncipherment";
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, key_usage);
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    // Extended key usage
    const char *ext_key_usage = is_server ? "serverAuth" : "clientAuth";
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage, ext_key_usage);
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    // Subject key identifier
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    // Authority key identifier
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_authority_key_identifier, "keyid:always,issuer");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    // Sign the certificate with CA key
    if (!X509_sign(cert, ca_key, EVP_sha256())) {
        X509_free(cert);
        return NULL;
    }

    X509_NAME_free(name);
    return cert;
}

// Function to save certificate and private key to files
void save_certificate_and_key(const char *cert_file, const char *key_file, X509 *cert, EVP_PKEY *key) {
    FILE *fp;

    // Save certificate
    fp = fopen(cert_file, "wb");
    if (fp) {
        PEM_write_X509(fp, cert);
        fclose(fp);
    }

    // Save private key
    fp = fopen(key_file, "wb");
    if (fp) {
        PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);
        fclose(fp);
    }
}

// Function to load or generate CA certificate and key
int load_or_generate_ca(EVP_PKEY **ca_key, X509 **ca_cert) {
    FILE *ca_cert_file = fopen("certs/ca-cert.pem", "r");
    FILE *ca_key_file = fopen("certs/ca-key.pem", "r");
    
    if (ca_cert_file && ca_key_file) {
        // Load existing CA certificate and key
        *ca_cert = PEM_read_X509(ca_cert_file, NULL, NULL, NULL);
        fclose(ca_cert_file);
        
        *ca_key = PEM_read_PrivateKey(ca_key_file, NULL, NULL, NULL);
        fclose(ca_key_file);
        
        if (*ca_cert && *ca_key) {
            printf("Loaded existing CA certificate and key\n");
            return 0;
        }
        
        // If loading failed, free any partially loaded data
        if (*ca_cert) X509_free(*ca_cert);
        if (*ca_key) EVP_PKEY_free(*ca_key);
    }
    
    // Generate new CA key pair
    *ca_key = generate_key();
    if (!*ca_key) {
        printf("Failed to generate CA key\n");
        return -1;
    }

    // Generate CA certificate
    *ca_cert = generate_ca_certificate(*ca_key);
    if (!*ca_cert) {
        EVP_PKEY_free(*ca_key);
        printf("Failed to generate CA certificate\n");
        return -1;
    }

    // Save CA certificate and key
    save_certificate_and_key("certs/ca-cert.pem", "certs/ca-key.pem", *ca_cert, *ca_key);
    printf("Generated new CA certificate and key\n");
    return 0;
}

// Function to generate server certificates
int generate_server_certificates() {
    // Create certificates directory if it doesn't exist
    if (!CreateDirectory("certs", NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        printf("Failed to create certs directory\n");
        return -1;
    }

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Generate server key pair
    EVP_PKEY *server_key = generate_key();
    if (!server_key) {
        printf("Failed to generate server key\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Load or generate CA
    EVP_PKEY *ca_key = NULL;
    X509 *ca_cert = NULL;
    if (load_or_generate_ca(&ca_key, &ca_cert) != 0) {
        EVP_PKEY_free(server_key);
        return -1;
    }

    // Generate server certificate
    X509 *server_cert = generate_certificate(server_key, ca_cert, ca_key, "127.0.0.1", 1);
    if (!server_cert) {
        printf("Failed to generate server certificate\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(server_key);
        EVP_PKEY_free(ca_key);
        X509_free(ca_cert);
        return -1;
    }

    // Create certs directory
    struct stat st = {0};
    if (stat("certs", &st) == -1) {
        if (!CreateDirectory("certs", NULL)) {
            printf("Failed to create certs directory\n");
            EVP_PKEY_free(server_key);
            EVP_PKEY_free(ca_key);
            X509_free(ca_cert);
            X509_free(server_cert);
            return -1;
        }
    }

    // Save certificates and keys
    FILE *fp;
    
    // Save server certificate
    fp = fopen("certs/server-cert.pem", "wb");
    if (!fp) {
        printf("Failed to open server certificate file for writing\n");
        goto cleanup;
    }
    if (!PEM_write_X509(fp, server_cert)) {
        printf("Failed to write server certificate\n");
        fclose(fp);
        goto cleanup;
    }
    fclose(fp);

    // Save server private key
    fp = fopen("certs/server-key.pem", "wb");
    if (!fp) {
        printf("Failed to open server key file for writing\n");
        goto cleanup;
    }
    if (!PEM_write_PrivateKey(fp, server_key, NULL, NULL, 0, NULL, NULL)) {
        printf("Failed to write server key\n");
        fclose(fp);
        goto cleanup;
    }
    fclose(fp);

    // Save CA certificate if it doesn't exist
    if (access("certs/ca-cert.pem", 0) != 0) {
        fp = fopen("certs/ca-cert.pem", "wb");
        if (!fp) {
            printf("Failed to open CA certificate file for writing\n");
            goto cleanup;
        }
        if (!PEM_write_X509(fp, ca_cert)) {
            printf("Failed to write CA certificate\n");
            fclose(fp);
            goto cleanup;
        }
        fclose(fp);
    }

    printf("Server certificates generated successfully\n");
    
    // Clean up
    EVP_PKEY_free(server_key);
    EVP_PKEY_free(ca_key);
    X509_free(ca_cert);
    X509_free(server_cert);
    return 0;

cleanup:
    if (server_key) EVP_PKEY_free(server_key);
    if (ca_key) EVP_PKEY_free(ca_key);
    if (ca_cert) X509_free(ca_cert);
    if (server_cert) X509_free(server_cert);
    return -1;
}

int main(int argc, char *argv[]) {
    WSADATA wsaData;
    SOCKET server_sock = INVALID_SOCKET;
    struct sockaddr_in server_addr;
    SSL_CTX *ctx;
    SSL *ssl = NULL;  // Declare SSL variable
    
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    int port = SERVER_PORT;
    if (argc > 1) port = atoi(argv[1]);

    printf("Starting VPN Server on port %d...\n", port);
    
    // Generate certificates if they don't exist
    if (_access("certs/server-cert.pem", 0) != 0 || _access("certs/server-key.pem", 0) != 0) {
        printf("Generating server certificates...\n");
        if (generate_server_certificates() != 0) {
            printf("Failed to generate certificates\n");
            return 1;
        }
    }

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create SSL context
    ctx = setupTLSServer();
    if (!ctx) {
        printf("Failed to create SSL context\n");
        return 1;
    }
    
    /*----------------Create a TCP connection -----------*/
    int listen_sock = setupTCPServer(port);
    if (listen_sock < 0) {
        printf("Failed to setup TCP server\n");
        return -1;
    }

    HANDLE tunfd = createTunDevice();
    if (tunfd == INVALID_HANDLE_VALUE) {
        printf("Failed to create TAP device\n");
        WSACleanup();
        return 1;
    }
    
    while (1) {
        struct sockaddr_in client_addr;
        int client_len = sizeof(client_addr);
        SOCKET client_sock;
        char client_ip[INET6_ADDRSTRLEN];  // Use INET6_ADDRSTRLEN for both IPv4/IPv6

        client_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock == INVALID_SOCKET) {
            printf("Accept failed\n");
            continue;
        }

        // Get client IP address
        if (inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip))) {
            printf("Client connected from %s\n", client_ip);
        } else {
            printf("Could not get client IP\n");
        }

        // Create new SSL structure for this connection
        ssl = SSL_new(ctx);
        if (!ssl) {
            printf("Error creating SSL structure\n");
            closesocket(client_sock);
            continue;
        }

        SSL_set_fd(ssl, client_sock);
        
        if (SSL_accept(ssl) <= 0) {
            printf("SSL accept error\n");
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            closesocket(client_sock);
            continue;
        }

        printf("SSL connection established!\n");

        int res = -1;
        while (1) {
            fd_set readFDSet;
            FD_ZERO(&readFDSet);
            FD_SET(client_sock, &readFDSet);
            if (select(client_sock + 1, &readFDSet, NULL, NULL, NULL) > 0) {
                if (FD_ISSET(client_sock, &readFDSet)) {
                    res = login_verification(ssl);
                    break;
                }
            }
        }
        
        reply_to_client(ssl, res);
        
        if (res != 1) {
            printf("Invalid Credentials. Breaking connection\n");
        } else {
            printf("Credentials Verified. Client is authorized\n");
            while (1) {
                fd_set readFDSet;
                FD_ZERO(&readFDSet);
                FD_SET((SOCKET)tunfd, &readFDSet);
                FD_SET(client_sock, &readFDSet);
                
                if (select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL) > 0) {
                    if (FD_ISSET(tunfd, &readFDSet)) tunSelected(tunfd, ssl);
                    if (FD_ISSET(client_sock, &readFDSet)) socketSelected(client_sock, ssl, tunfd);
                }
            }
        }
        
        // Clean up
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        closesocket(client_sock);
    }
    
    SSL_CTX_free(ctx);
    CloseHandle(tunfd);
    WSACleanup();
    return 0;
}
