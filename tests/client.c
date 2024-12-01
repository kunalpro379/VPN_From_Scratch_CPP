#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
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
#include <ws2tcpip.h>
#include <conio.h>
#include <winioctl.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#define BUFF_SIZE 2000
#define SERVER_PORT 4433  // Match server port

// Message headers for authentication
struct cred_header {
    uint16_t user_len;  // Length of username
    uint16_t pwd_len;   // Length of password
};

struct tls_header {
    uint16_t tlsh_len;  // Length of the data
    uint8_t  tlsh_type; // Type of the message
};

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
#define ADAPTER_KEY "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define USEC_PER_SEC    1000000
#define DEFAULT_SLEEP_TIME (USEC_PER_SEC / 100)
#define TAP_WIN_SUFFIX ".tap"

// Function declarations
SSL_CTX* setup_client_ctx(void);
HANDLE createTunDevice();
void tunSelected(HANDLE tunfd, int sockfd, SSL *ssl);
void socketSelected(HANDLE tunfd, int sockfd, SSL *ssl);
void reading_result(SSL *ssl);
static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx);

char* find_tap_guid() {
    HKEY adapter_key;
    DWORD len;
    char *guid = NULL;
    
    printf("Looking for TAP adapter...\n");
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
    return guid;
}

HANDLE createTunDevice() {
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

    char *guid = find_tap_guid();
    if (guid == NULL) {
        printf("\nError: No TAP-Windows adapters found.\n");
        printf("Please install OpenVPN or TAP-Windows driver from:\n");
        printf("https://openvpn.net/community-downloads/\n\n");
        return INVALID_HANDLE_VALUE;
    }

    char device_path[512];
    snprintf(device_path, sizeof(device_path), "\\\\.\\Global\\%s.tap", guid);
    printf("Opening TAP device: %s\n", device_path);

HANDLE handle = CreateFileA(device_path,
    GENERIC_READ | GENERIC_WRITE,
    0, // No sharing
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_SYSTEM, // Remove FILE_FLAG_OVERLAPPED
    NULL);

    if (handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        printf("\nError: Could not open TAP device (Error: %lu)\n", error);
        printf("Error details: ");
        LPVOID lpMsgBuf;
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | 
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR) &lpMsgBuf,
            0, NULL);
        printf("%s\n", (char*)lpMsgBuf);
        LocalFree(lpMsgBuf);

        // Try to take ownership of the TAP device
        printf("Attempting to take ownership of TAP device...\n");
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "takeown /f \\\\.\\Global\\%s.tap", guid);
        system(cmd);

        // Try to reset the TAP adapter with the correct name
        printf("Attempting to reset TAP adapter...\n");
        snprintf(cmd, sizeof(cmd), "netsh interface set interface \"OpenVPN TAP-Windows6\" admin=disable");
        system(cmd);
        Sleep(1000);
        snprintf(cmd, sizeof(cmd), "netsh interface set interface \"OpenVPN TAP-Windows6\" admin=enable");
        system(cmd);
        Sleep(1000);

  handle = CreateFileA(device_path,
    GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_SYSTEM, // Remove FILE_FLAG_OVERLAPPED
    NULL);

        if (handle == INVALID_HANDLE_VALUE) {
            error = GetLastError();
            printf("Still could not open TAP device (Error: %lu)\n", error);
            printf("Error details: ");
            FormatMessage(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | 
                FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL,
                error,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPTSTR) &lpMsgBuf,
                0, NULL);
            printf("%s\n", (char*)lpMsgBuf);
            LocalFree(lpMsgBuf);

            printf("\nTroubleshooting steps:\n");
            printf("1. Open Device Manager\n");
            printf("2. Find 'OpenVPN TAP-Windows6' under Network Adapters\n");
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
    ULONG ip_addr = htonl(0x0A0A0A02);  // 10.10.10.2
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
    printf("TAP adapter IP: 10.10.10.2/24\n");
    free(guid);
    return handle;
}

void tunSelected(HANDLE tunfd, int sockfd, SSL *ssl) {
    int len;
    char buff[BUFF_SIZE];
    char buffer[4];
    memset(buffer, 0, 4);
    struct tls_header *tls = (struct tls_header *)buffer;

    printf("Got a packet from TUN\n");
    memset(buff, 0, BUFF_SIZE);
    DWORD bytes_read;
    if (ReadFile(tunfd, buff, BUFF_SIZE, &bytes_read, NULL)) {
        // First send the TLS header
        tls->tlsh_len = htons(bytes_read);
        len = SSL_write(ssl, tls, sizeof(struct tls_header));
        if (len <= 0) {
            printf("Error sending TLS header\n");
            return;
        }
        
        // Then send the actual data
        len = SSL_write(ssl, buff, bytes_read);
        if (len > 0) {
            printf("Forwarded %d bytes to the SSL tunnel\n", len);
        } else {
            printf("Error forwarding data to SSL tunnel\n");
        }
    }
}

// void socketSelected(HANDLE tunfd, int sockfd, SSL *ssl) {
//     int len;
//     char buff[BUFF_SIZE];

//     printf("Got a packet from the tunnel\n");
//     memset(buff, 0, BUFF_SIZE);
//     len = SSL_read(ssl, buff, BUFF_SIZE);

//     if (len == 0) {
//         printf("The client disconnected\n");
//         exit(-1);
//     }

//     DWORD bytes_written;
//     WriteFile(tunfd, buff, len, &bytes_written, NULL);
//     printf("Forwarded %d bytes to TUN\n", bytes_written);
// }
void socketSelected(HANDLE tunfd, int sockfd, SSL *ssl) {
    int len, length;
    char buff[BUFF_SIZE];
    char buffer[4];
    memset(buffer, 0, 4);
    struct tls_header *tls = (struct tls_header *)buffer;

    printf("Got a packet from the tunnel\n");
    
    // Read TLS header first
    len = SSL_read(ssl, tls, sizeof(struct tls_header));
    if (len <= 0) {
        printf("Error reading TLS header\n");
        return;
    }
    
    length = ntohs(tls->tlsh_len);
    if (length > BUFF_SIZE) {
        printf("Packet too large: %d\n", length);
        return;
    }
    
    // Read the actual data
    len = SSL_read(ssl, buff, length);
    if (len <= 0) {
        printf("Error reading data from tunnel\n");
        return;
    }
    
    DWORD bytes_written;
    if (WriteFile(tunfd, buff, len, &bytes_written, NULL)) {
        printf("Forwarded %d bytes to TUN\n", bytes_written);
    } else {
        printf("Error writing to TUN device\n");
    }
}
static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    if (!preverify_ok) {
        int err = X509_STORE_CTX_get_error(ctx);
        int depth = X509_STORE_CTX_get_error_depth(ctx);
        X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
        X509_NAME *subject = X509_get_subject_name(cert);
        char buf[256];

        X509_NAME_oneline(subject, buf, sizeof(buf));
        printf("Certificate verification error at depth: %d\n", depth);
        printf("  Subject: %s\n", buf);
        printf("  Error %d: %s\n", err, X509_verify_cert_error_string(err));
    }
    return preverify_ok;
}

SSL_CTX* setup_client_ctx(void) {
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Set minimum TLS version
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    // Set verify modes
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    SSL_CTX_set_verify_depth(ctx, 4);

    // Load trusted CA certificates
    if (!SSL_CTX_load_verify_locations(ctx, "certs/ca-cert.pem", NULL)) {
        printf("Failed to load CA certificate\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Load client certificate and private key
    if (!SSL_CTX_use_certificate_file(ctx, "certs/client-cert.pem", SSL_FILETYPE_PEM)) {
        printf("Failed to load client certificate\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (!SSL_CTX_use_PrivateKey_file(ctx, "certs/client-key.pem", SSL_FILETYPE_PEM)) {
        printf("Failed to load client private key\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Verify private key
    if (!SSL_CTX_check_private_key(ctx)) {
        printf("Private key does not match the certificate public key\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

int setupTCPClient(char *server_ip, int port) {
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed with error: %d\n", WSAGetLastError());
        return -1;
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd == INVALID_SOCKET) {
        printf("Socket creation failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, server_ip, &(server_addr.sin_addr)) != 1) {
        printf("Invalid address/Address not supported: %s\n", server_ip);
        closesocket(sockfd);
        WSACleanup();
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        int error = WSAGetLastError();
        printf("Connection failed with error: %d\n", error);
        switch(error) {
            case WSAECONNREFUSED:
                printf("Connection refused. Make sure the VPN server is running.\n");
                break;
            case WSAEHOSTUNREACH:
                printf("Host unreachable. Check your network connection.\n");
                break;
            case WSAETIMEDOUT:
                printf("Connection timed out. Server might be down or blocked by firewall.\n");
                break;
            case WSAENETUNREACH:
                printf("Network is unreachable. Check your network connection.\n");
                break;
            default:
                printf("Unknown error occurred.\n");
        }
        closesocket(sockfd);
        WSACleanup();
        return -1;
    }

    return sockfd;
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
    if (!ca_cert) return NULL;

    X509_NAME *name = X509_NAME_new();
    if (!name) {
        X509_free(ca_cert);
        return NULL;
    }

    // Set certificate details
    if (!X509_set_version(ca_cert, 2)) goto err;  // X509v3

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
    
    // Basic Constraints
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "critical,CA:TRUE,pathlen:0");
    if (!ext || !X509_add_ext(ca_cert, ext, -1)) goto err;
    X509_EXTENSION_free(ext);

    // Key Usage
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, "critical,keyCertSign,cRLSign");
    if (!ext || !X509_add_ext(ca_cert, ext, -1)) goto err;
    X509_EXTENSION_free(ext);

    // Subject Key Identifier
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
    if (!ext || !X509_add_ext(ca_cert, ext, -1)) goto err;
    X509_EXTENSION_free(ext);

    // Self-sign the CA certificate
    if (!X509_sign(ca_cert, ca_key, EVP_sha256())) goto err;

    X509_NAME_free(name);
    return ca_cert;

err:
    X509_NAME_free(name);
    X509_free(ca_cert);
    return NULL;
}

// Function to generate a server/client certificate signed by CA
X509* generate_certificate(EVP_PKEY *key, X509 *ca_cert, EVP_PKEY *ca_key, const char *cn, int is_server) {
    X509 *cert = X509_new();
    if (!cert) return NULL;

    X509_NAME *name = X509_NAME_new();
    if (!name) {
        X509_free(cert);
        return NULL;
    }

    // Set certificate version (X509v3)
    if (!X509_set_version(cert, 2)) goto err;

    // Set serial number
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    ASN1_INTEGER_set(serial, 2);
    if (!X509_set_serialNumber(cert, serial)) goto err;
    ASN1_INTEGER_free(serial);

    // Set validity period
    if (!X509_gmtime_adj(X509_get_notBefore(cert), 0)) goto err;
    if (!X509_gmtime_adj(X509_get_notAfter(cert), 31536000L)) goto err; // Valid for 1 year

    // Set certificate subject
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"VPN", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)cn, -1, -1, 0);

    if (!X509_set_subject_name(cert, name)) goto err;
    if (!X509_set_issuer_name(cert, X509_get_subject_name(ca_cert))) goto err;

    if (!X509_set_pubkey(cert, key)) goto err;

    // Add extensions
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ca_cert, cert, NULL, NULL, 0);

    X509_EXTENSION *ext;

    // Basic Constraints
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "critical,CA:FALSE");
    if (!ext || !X509_add_ext(cert, ext, -1)) goto err;
    X509_EXTENSION_free(ext);

    // Key Usage
    const char *key_usage = is_server ? 
        "critical,digitalSignature,keyEncipherment,keyAgreement" :
        "critical,digitalSignature,keyEncipherment";
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, key_usage);
    if (!ext || !X509_add_ext(cert, ext, -1)) goto err;
    X509_EXTENSION_free(ext);

    // Extended Key Usage
    const char *ext_key_usage = is_server ? "serverAuth" : "clientAuth";
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage, ext_key_usage);
    if (!ext || !X509_add_ext(cert, ext, -1)) goto err;
    X509_EXTENSION_free(ext);

    // Authority Key Identifier (must be added before Subject Key Identifier)
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_authority_key_identifier, "keyid");
    if (!ext || !X509_add_ext(cert, ext, -1)) goto err;
    X509_EXTENSION_free(ext);

    // Subject Key Identifier
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
    if (!ext || !X509_add_ext(cert, ext, -1)) goto err;
    X509_EXTENSION_free(ext);

    // Sign the certificate with CA key
    if (!X509_sign(cert, ca_key, EVP_sha256())) goto err;

    X509_NAME_free(name);
    return cert;

err:
    ERR_print_errors_fp(stderr);
    X509_NAME_free(name);
    X509_free(cert);
    return NULL;
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

// Function to generate client certificates
int generate_client_certificates() {
    // Create certificates directory if it doesn't exist
    if (!CreateDirectory("certs", NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        printf("Failed to create certs directory\n");
        return -1;
    }

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Generate client key pair
    EVP_PKEY *client_key = generate_key();
    if (!client_key) {
        printf("Failed to generate client key\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Load or generate CA
    EVP_PKEY *ca_key = NULL;
    X509 *ca_cert = NULL;
    if (load_or_generate_ca(&ca_key, &ca_cert) != 0) {
        EVP_PKEY_free(client_key);
        return -1;
    }

    // Generate client certificate
    X509 *client_cert = generate_certificate(client_key, ca_cert, ca_key, "VPN-Client", 0);
    if (!client_cert) {
        printf("Failed to generate client certificate\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(client_key);
        EVP_PKEY_free(ca_key);
        X509_free(ca_cert);
        return -1;
    }

    // Create certs directory
    struct stat st = {0};
    if (stat("certs", &st) == -1) {
        if (!CreateDirectory("certs", NULL)) {
            printf("Failed to create certs directory\n");
            EVP_PKEY_free(client_key);
            EVP_PKEY_free(ca_key);
            X509_free(ca_cert);
            X509_free(client_cert);
            return -1;
        }
    }

    // Save client certificate and key
    FILE *fp;
    
    // Save client certificate
    fp = fopen("certs/client-cert.pem", "wb");
    if (!fp) {
        printf("Failed to open client certificate file for writing\n");
        goto cleanup;
    }
    if (!PEM_write_X509(fp, client_cert)) {
        printf("Failed to write client certificate\n");
        fclose(fp);
        goto cleanup;
    }
    fclose(fp);

    // Save client private key
    fp = fopen("certs/client-key.pem", "wb");
    if (!fp) {
        printf("Failed to open client key file for writing\n");
        goto cleanup;
    }
    if (!PEM_write_PrivateKey(fp, client_key, NULL, NULL, 0, NULL, NULL)) {
        printf("Failed to write client key\n");
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

    printf("Client certificates generated successfully\n");
    
    // Clean up
    EVP_PKEY_free(client_key);
    EVP_PKEY_free(ca_key);
    X509_free(ca_cert);
    X509_free(client_cert);
    return 0;

cleanup:
    if (client_key) EVP_PKEY_free(client_key);
    if (ca_key) EVP_PKEY_free(ca_key);
    if (ca_cert) X509_free(ca_cert);
    if (client_cert) X509_free(client_cert);
    return -1;
}

// Function to read result from SSL connection
void reading_result(SSL *ssl) {
    char buff[1024];
    int len = SSL_read(ssl, buff, sizeof(buff) - 1);
    if (len > 0) {
        buff[len] = '\0';
        printf("Server response: %s\n", buff);
    } else {
        printf("Error reading from server\n");
        ERR_print_errors_fp(stderr);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <server_ip> <port>\n", argv[0]);
        return 1;
    }

    char *server_ip;
    int port = atoi(argv[2]);

    // Generate certificates if they don't exist
    if (_access("certs/client-cert.pem", 0) != 0 || _access("certs/client-key.pem", 0) != 0) {
        printf("Generating client certificates...\n");
        if (generate_client_certificates() != 0) {
            printf("Failed to generate certificates\n");
            return 1;
        }
    }

    server_ip = argv[1];

    // Initialize SSL context
    SSL_CTX *ctx = setup_client_ctx();
    
    // Create TUN device
    HANDLE tunfd = createTunDevice();
    if (tunfd == INVALID_HANDLE_VALUE) {
        printf("Failed to create TUN device\n");
        exit(1);
    }

    // Connect to VPN server
    int sockfd = setupTCPClient(server_ip, port);
    if (sockfd < 0) {
        printf("Failed to connect to VPN server\n");
        exit(1);
    }

    // Create SSL connection
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        printf("Error creating SSL structure\n");
        exit(1);
    }

    SSL_set_fd(ssl, sockfd);

    // Set hostname verification to none for IP-based connection
    SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    printf("SSL connection established with %s\n", SSL_get_cipher(ssl));
    
    // Verify server certificate
    X509 *server_cert = SSL_get_peer_certificate(ssl);
    if (server_cert) {
        printf("Server certificate verified\n");
        X509_free(server_cert);
    } else {
        printf("Error: No server certificate received\n");
        exit(1);
    }

    // Authentication loop
    char username[50], password[50];
    printf("Username: ");
    scanf("%s", username);
    printf("Password: ");
    scanf("%s", password);
// 
//     // Send credentials
//     char buffer[1024];
//     snprintf(buffer, sizeof(buffer), "%s:%s", username, password);
//     SSL_write(ssl, buffer, strlen(buffer));

// Send credentials
char buffer[1024];
struct tls_header *tls = (struct tls_header *)buffer;
struct cred_header *cred = (struct cred_header *)(buffer + sizeof(struct tls_header));
char *data = buffer + sizeof(struct tls_header) + sizeof(struct cred_header);

// Set credential lengths
cred->user_len = htons(strlen(username));
cred->pwd_len = htons(strlen(password));

// Copy credentials after the headers
memcpy(data, username, strlen(username));
data += strlen(username);
memcpy(data, password, strlen(password));

// Set TLS header length (total length of cred header + username + password)
tls->tlsh_len = htons(sizeof(struct cred_header) + strlen(username) + strlen(password));

// Send the entire buffer
int total_len = sizeof(struct tls_header) + sizeof(struct cred_header) + strlen(username) + strlen(password);
SSL_write(ssl, buffer, total_len);

    // Read authentication result
    reading_result(ssl);

    // Main VPN loop
    while (1) {
        fd_set readFDSet;
        FD_ZERO(&readFDSet);
        FD_SET(sockfd, &readFDSet);
        FD_SET(_open_osfhandle((intptr_t)tunfd, 0), &readFDSet);
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

        if (FD_ISSET(_open_osfhandle((intptr_t)tunfd, 0), &readFDSet)) tunSelected(tunfd, sockfd, ssl);
        if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd, ssl);
    }

    // Cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesocket(sockfd);
    CloseHandle(tunfd);
    WSACleanup();
    return 0;
}
