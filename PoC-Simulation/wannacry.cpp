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
#include <random>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

class NetworkRecon {
private:
    struct NetConfig {
        std::string network;
        std::string mask;
        int prefix;
    };

    static std::atomic<int> scanned_count;
    static std::atomic<int> target_count;

public:
    static void Execute() {
        NetConfig config = AcquireNetworkConfig();
        if (!config.network.empty()) {
            std::cout << "[+] Acquired network: " << config.network << "/" << config.prefix << std::endl;
            scanned_count = 0;
            target_count = 0;
            
            PerformScan(config);
        }
    }

private:
    static NetConfig AcquireNetworkConfig() {
        PIP_ADAPTER_ADDRESSES adapters = nullptr;
        ULONG buf_size = 0;
        NetConfig config = {};
        
        DWORD ret = GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_INCLUDE_GATEWAYS,
            nullptr,
            adapters,
            &buf_size
        );
        
        if (ret == ERROR_BUFFER_OVERFLOW) {
            adapters = (PIP_ADAPTER_ADDRESSES)malloc(buf_size);
            ret = GetAdaptersAddresses(
                AF_INET,
                GAA_FLAG_INCLUDE_GATEWAYS,
                nullptr,
                adapters,
                &buf_size
            );
            
            if (ret == ERROR_SUCCESS) {
                PIP_ADAPTER_ADDRESSES adapter = adapters;
                while (adapter) {
                    if (ValidateAdapter(adapter)) {
                        config = ExtractConfig(adapter);
                        break;
                    }
                    adapter = adapter->Next;
                }
            }
            free(adapters);
        }
        
        return config;
    }

    static bool ValidateAdapter(PIP_ADAPTER_ADDRESSES adapter) {
        if (adapter->OperStatus != IfOperStatusUp) return false;
        if (adapter->FirstGatewayAddress == nullptr) return false;
        if (adapter->FirstUnicastAddress == nullptr) return false;
        if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) return false;
        return true;
    }

    static NetConfig ExtractConfig(PIP_ADAPTER_ADDRESSES adapter) {
        NetConfig config;
        PIP_ADAPTER_UNICAST_ADDRESS unicast = adapter->FirstUnicastAddress;
        
        if (unicast && unicast->Address.lpSockaddr->sa_family == AF_INET) {
            sockaddr_in* ipv4 = (sockaddr_in*)unicast->Address.lpSockaddr;
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);
            
            std::string mask = CalculateMask(unicast->OnLinkPrefixLength);
            config.network = CalculateNetwork(ip_str, mask);
            config.mask = mask;
            config.prefix = unicast->OnLinkPrefixLength;
        }
        
        return config;
    }

    static void PerformScan(const NetConfig& config) {
        std::vector<std::string> targets = GenerateTargets(config);
        std::vector<std::string> vulnerable;
        
        std::cout << "[+] Scanning " << targets.size() << " potential targets" << std::endl;
        
        std::cout << CheckPort("192.169.180.18", 445) << " hehe" << std::endl; // Warm-up connection

        for (const auto& target : targets) {
            std::cout << "[*] Checking: " << target << " ... ";

            if (CheckPort(target, 445)) {
                std::cout << "SMBv1 OPEN" << std::endl;
                std::cout << "[!] Target acquired: " << target << std::endl;
                vulnerable.push_back(target);
                target_count++;
            } else {
                std::cout << "closed" << std::endl;
            }
            
            scanned_count++;
            ApplyDelay();
        }
        
        ReportFindings(vulnerable, targets.size());
    }

    static std::vector<std::string> GenerateTargets(const NetConfig& config) {
        std::vector<std::string> targets;
        in_addr net_addr;
        inet_pton(AF_INET, config.network.c_str(), &net_addr);
        
        int total_hosts = (1 << (32 - config.prefix)) - 2;
        if (total_hosts <= 0) return targets;
        
        std::vector<int> host_nums;
        for (int i = 1; i <= total_hosts; i++) {
            host_nums.push_back(i);
        }
        
        std::random_device rd;
        std::shuffle(host_nums.begin(), host_nums.end(), rd);

        for (int host_num : host_nums) {
            uint32_t host_ip = ntohl(net_addr.s_addr) + host_num;
            in_addr ip;
            ip.s_addr = htonl(host_ip);
            
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip, ip_str, INET_ADDRSTRLEN);
            targets.push_back(ip_str);
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
        
        int result = connect(sock, (sockaddr*)&target, sizeof(target));
        
        if (result == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                closesocket(sock);
                return false;
            }
        }
        
        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);
        
        timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 300000;
        
        result = select(0, NULL, &writefds, NULL, &timeout);
        closesocket(sock);
        
        return (result > 0);
    }

    static void ApplyDelay() {
        std::random_device rd;
        std::uniform_int_distribution<> delay(20, 200);
        Sleep(delay(rd));
        
        if (scanned_count % 30 == 0) {
            std::uniform_int_distribution<> long_delay(500, 1000);
            Sleep(long_delay(rd));
        }
    }

    static void ReportFindings(const std::vector<std::string>& targets, int total) {
        std::cout << "\n[+] Scan completed: " << total << " hosts evaluated" << std::endl;
        std::cout << "[+] Vulnerable targets: " << targets.size() << std::endl;
        
        if (!targets.empty()) {
            std::cout << "[!] Targets identified:" << std::endl;
            for (const auto& target : targets) {
                std::cout << "    " << target << std::endl;
            }
        }
    }

    static std::string CalculateMask(ULONG prefix) {
        if (prefix > 32) return "0.0.0.0";
        uint32_t mask_val = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF;
        in_addr mask_addr;
        mask_addr.s_addr = htonl(mask_val);
        char mask_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &mask_addr, mask_str, INET_ADDRSTRLEN);
        return std::string(mask_str);
    }

    static std::string CalculateNetwork(const std::string& ip, const std::string& mask) {
        in_addr ip_addr, mask_addr, net_addr;
        inet_pton(AF_INET, ip.c_str(), &ip_addr);
        inet_pton(AF_INET, mask.c_str(), &mask_addr);
        net_addr.s_addr = ip_addr.s_addr & mask_addr.s_addr;
        char net_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &net_addr, net_str, INET_ADDRSTRLEN);
        return std::string(net_str);
    }
};

std::atomic<int> NetworkRecon::scanned_count(0);
std::atomic<int> NetworkRecon::target_count(0);

int main() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    
    NetworkRecon::Execute();
    
    WSACleanup();
    return 0;
}