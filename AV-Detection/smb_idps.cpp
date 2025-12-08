#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)

std::vector<std::string> blockedIPs;

struct IPHeader {
    BYTE  ver_ihl;
    BYTE  tos;
    WORD  length;
    WORD  id;
    WORD  flags_fo;
    BYTE  ttl;
    BYTE  protocol;
    WORD  checksum;
    DWORD src_addr;
    DWORD dst_addr;
};

struct TCPHeader {
    WORD  src_port;
    WORD  dst_port;
    DWORD seq_num;
    DWORD ack_num;
    BYTE  data_offset;
    BYTE  flags;
    WORD  window;
    WORD  checksum;
    WORD  urgent_ptr;
};

void RemoveBlockRule(const std::string& ipAddress) {
    std::string ruleName = "BLOCK_ETERNALBLUE_" + ipAddress;
    std::string cmd = "netsh advfirewall firewall delete rule name=\"" + ruleName + "\"";
    WinExec(cmd.c_str(), SW_HIDE);
    std::cout << "[INFO] Removed block rule for IP: " << ipAddress << std::endl;
}

void BlockAttacker(const std::string& ipAddress) {
    for (const auto& ip : blockedIPs) {
        if (ip == ipAddress) return;
    }

    std::cout << "\n[!!!] ATTACK DETECTED! -> BLOCKING IP: " << ipAddress << std::endl;
    
    std::string ruleName = "BLOCK_ETERNALBLUE_" + ipAddress;
    std::string cmd = "netsh advfirewall firewall add rule name=\"" + ruleName + "\" dir=in action=block remoteip=" + ipAddress;
    WinExec(cmd.c_str(), SW_HIDE);

    blockedIPs.push_back(ipAddress);
}

BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT) {
        std::cout << "\n[INFO] Shutting down... Cleaning up Firewall rules..." << std::endl;
        for (const auto& ip : blockedIPs) {
            RemoveBlockRule(ip);
        }
        std::cout << "[INFO] Cleanup complete. Exiting now." << std::endl;
        Sleep(500); 
        ExitProcess(0); 
    }
    return TRUE;
}

bool DetectEternalBlueSignature(const char* payload, int size) {
    if (size < 100) return false;

    bool isSMB = false;
    for(int i=0; i < size - 4 && i < 64; i++) {
        if ((payload[i] == 0xFF || payload[i] == 0xFE) && 
            payload[i+1] == 'S' && payload[i+2] == 'M' && payload[i+3] == 'B') {
            isSMB = true;
            break;
        }
    }
    if (!isSMB) return false;

    int consecutive_A = 0;
    int consecutive_NOP = 0;

    for (int i = 0; i < size; i++) {
        if (payload[i] == 0x41) consecutive_A++; else consecutive_A = 0;
        if (payload[i] == 0x90) consecutive_NOP++; else consecutive_NOP = 0;

        if (consecutive_A > 100 || consecutive_NOP > 100) {
            return true;
        }
    }
    return false;
}

std::string GetLocalIP() {
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) return "";
    struct hostent* host = gethostbyname(hostname);
    if (host) {
        struct in_addr** addr_list = (struct in_addr**)host->h_addr_list;
        for (int i = 0; addr_list[i] != NULL; i++) return inet_ntoa(*addr_list[i]);
    }
    return "";
}

int main() {
    if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE)) {
        std::cerr << "Error: Could not set console control handler.\n";
        return 1;
    }

    std::cout << "=================================================\n";
    std::cout << "   ANTI-ETERNALBLUE DEMO (Auto Cleanup Mode)     \n";
    std::cout << "=================================================\n";

    system("netsh advfirewall firewall delete rule name=all | findstr \"BLOCK_ETERNALBLUE_\" > nul");

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return 1;

    SOCKET sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (sniffer == INVALID_SOCKET) {
        std::cerr << "[-] Error: Run as Administrator!\n";
        system("pause");
        return 1;
    }

    std::string myIP = GetLocalIP();
    if (myIP.empty()) return 1;
    
    sockaddr_in local;
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = inet_addr(myIP.c_str());
    local.sin_port = 0;

    if (bind(sniffer, (sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
        std::cerr << "[-] Bind failed. IP: " << myIP << "\n";
        return 1;
    }

    DWORD j = 1;
    ioctlsocket(sniffer, SIO_RCVALL, &j);

    std::cout << "[+] Protecting: " << myIP << "\n";
    std::cout << "[+] Status: READY TO BLOCK ATTACKS.\n";
    std::cout << "[!] Closing this program will DISABLE protection.\n\n";

    char buffer[65536];
    while (true) {
        int size = recv(sniffer, buffer, sizeof(buffer), 0);
        if (size > 0) {
            IPHeader* ipHeader = (IPHeader*)buffer;
            int ipHeaderLen = (ipHeader->ver_ihl & 0x0F) * 4;

            if (ipHeader->protocol == IPPROTO_TCP) {
                TCPHeader* tcpHeader = (TCPHeader*)(buffer + ipHeaderLen);
                int portDst = ntohs(tcpHeader->dst_port);

                if (portDst == 445) {
                    int tcpHeaderLen = ((tcpHeader->data_offset >> 4) * 4);
                    char* payload = buffer + ipHeaderLen + tcpHeaderLen;
                    int payloadSize = size - ipHeaderLen - tcpHeaderLen;

                    if (payloadSize > 0) {
                        if (DetectEternalBlueSignature(payload, payloadSize)) {
                            in_addr addr;
                            addr.s_addr = ipHeader->src_addr;
                            std::string attackerIP = inet_ntoa(addr);
                            
                            BlockAttacker(attackerIP);
                        }
                    }
                }
            }
        }
    }

    closesocket(sniffer);
    WSACleanup();
    return 0;
}