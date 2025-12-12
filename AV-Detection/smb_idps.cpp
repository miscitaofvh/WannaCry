#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)
#define MAX_PACKET_SIZE 65535

#pragma pack(push, 1)

struct IPHeader {
    unsigned char  ver_ihl;        
    unsigned char  tos;            
    unsigned short total_len;      
    unsigned short id;             
    unsigned short flags_fo;       
    unsigned char  ttl;            
    unsigned char  protocol;       
    unsigned short checksum;       
    struct in_addr srcAddr;        
    struct in_addr destAddr;       
};

struct TCPHeader {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int   sequence;
    unsigned int   ack;
    unsigned char  data_offset;  
    unsigned char  flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_ptr;
};

// Cấu trúc NetBIOS Session Header (4 bytes đầu tiên của payload TCP)
struct NetBIOS_Header {
    unsigned char  Type;      // 0x00 = Message
    unsigned char  Length[3]; // Big Endian Length (24 bits)
};

// Cấu trúc SMB Header chuẩn (bắt đầu sau NetBIOS)
struct SMB_Header {
    unsigned char  Protocol[4];   // 0xFF 'S' 'M' 'B'
    unsigned char  Command;       // 0x32 hoặc 0x33
    unsigned int   Status;
    unsigned char  Flags;
    unsigned short Flags2;
    unsigned short PIDHigh;
    unsigned char  Signature[8];
    unsigned short Reserved;
    unsigned short TID;
    unsigned short PID;
    unsigned short UID;
    unsigned short MID;
};
#pragma pack(pop)

std::vector<std::string> activeBlockRules; // Lưu danh sách các IP đã block để tí nữa xóa
bool isRunning = true;

// Hàm lấy giá trị 24-bit big endian từ NetBIOS Header
unsigned int getNetBIOSLength(unsigned char* lenPtr) {
    return (lenPtr[0] << 16) | (lenPtr[1] << 8) | (lenPtr[2]);
}

void RemoveBlockRule(const std::string& ipAddress) {
    std::string ruleName = "BLOCK_ETERNALBLUE_" + ipAddress;
    // Lệnh xóa rule trong Windows Firewall
    std::string cmd = "netsh advfirewall firewall delete rule name=\"" + ruleName + "\"";
    WinExec(cmd.c_str(), SW_HIDE);
    std::cout << "[CLEANUP] Da go bo rule chan IP: " << ipAddress << std::endl;
}

BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT) {
        std::cout << "\n\n[INFO] Dang tat chuong trinh... Dang xoa cac rule Firewall..." << std::endl;
        isRunning = false;
        
        // Duyệt qua danh sách đã chặn và xóa hết
        for (const auto& ip : activeBlockRules) {
            RemoveBlockRule(ip);
        }
        std::cout << "[INFO] Hoan tat. Bye bye!" << std::endl;
        Sleep(1000);
        ExitProcess(0);
    }
    return TRUE;
}

void BlockAttacker(const std::string& ipAddress) {
    // 1. Kiểm tra xem IP đã có trong danh sách bộ nhớ chưa
    for (const auto& ruleIP : activeBlockRules) {
        if (ruleIP == ipAddress) return;
    }

    std::cout << "\n[!!!] BLOCKING IP: " << ipAddress << "..." << std::endl;
    
    std::string ruleName = "BLOCK_ETERNALBLUE_" + ipAddress;
    
    // 2. Cập nhật câu lệnh Netsh mạnh mẽ hơn (profile=any, enable=yes)
    // Dùng stringstream hoặc cộng chuỗi cẩn thận
    std::string cmd = "netsh advfirewall firewall add rule name=\"" + ruleName + 
                      "\" dir=in action=block remoteip=" + ipAddress + 
                      " protocol=any enable=yes profile=any";

    // 3. Sử dụng system() để thực thi. 
    // Lưu ý: system() sẽ trả về 0 nếu thành công.
    int result = system(cmd.c_str());

    // 4. Chỉ thêm vào danh sách activeBlockRules NẾU lệnh chặn thành công
    if (result == 0) {
        std::cout << "[+] SUCCESS: IP " << ipAddress << " has been blocked in Windows Firewall." << std::endl;
        activeBlockRules.push_back(ipAddress);
    } else {
        std::cout << "[-] FAILED: Could not add firewall rule. Run as Administrator!" << std::endl;
        // KHÔNG thêm vào activeBlockRules để lần sau nó thử chặn lại
    }
}

void analyzeSMB(unsigned char* payload, int payloadSize, struct in_addr srcAddr) {
    // 1. Kiểm tra kích thước tối thiểu (NetBIOS 4 bytes + SMB Header 32 bytes)
    if (payloadSize < 36) return; 

    // 2. Kiểm tra NetBIOS Session Service (Byte đầu thường là 0x00)
    // Và kiểm tra Magic SMB: 0xFF 'S' 'M' 'B' tại offset 4
    if (payload[4] != 0xFF || payload[5] != 'S' || payload[6] != 'M' || payload[7] != 'B') {
        return; // Không phải SMB packet chuẩn
    }

    // Parse Headers
    NetBIOS_Header* nbHeader = (NetBIOS_Header*)payload;
    SMB_Header* smbHeader = (SMB_Header*)(payload + 4);
    
    unsigned int netBIOSLen = getNetBIOSLength(nbHeader->Length);
    unsigned char command = smbHeader->Command;

    if (command == 0xA0) {
        
        // Word Count (WCT) nằm ngay sau SMB Header (offset 4 + 32 = 36)
        int wctOffset = 36;
        int totalDataCountOffset = 44;

        if (payloadSize < totalDataCountOffset + 4) return; // Không đủ dữ liệu để đọc

        // Đọc 4 bytes TotalDataCount (Lưu ý: Little Endian trong SMB)
        unsigned int* pTotalDataCount = (unsigned int*)(payload + totalDataCountOffset);
        unsigned int totalDataCount = *pTotalDataCount;

        if (totalDataCount > netBIOSLen) {
            std::string attackerIP = inet_ntoa(srcAddr);
            
            std::cout << "\n[!!!] ALERT: MALICIOUS SMB PACKET DETECTED (NT_TRANSACT 0xA0)" << std::endl;
            std::cout << "      Src IP: " << attackerIP << std::endl;
            std::cout << "      [+] NetBIOS Length (Real): " << netBIOSLen << " bytes" << std::endl;
            std::cout << "      [+] Total Data Count (Fake): " << totalDataCount << " bytes" << std::endl;
            std::cout << "      [!] DISCREPANCY: Payload is too small for requested allocation!" << std::endl;
            
            BlockAttacker(attackerIP);
        } 

        std::cout << "--------------------------------------------------------" << std::endl;
    }
}

int main() {
    if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE)) {
        std::cerr << "Loi: Khong the dang ky Console Handler.\n";
        return 1;
    }

    WSADATA wsaData;
    SOCKET sniffSocket;
    char hostname[100];
    struct hostent* local;
    struct sockaddr_in dest;
    char* buffer = new char[MAX_PACKET_SIZE];
    int count = 0;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return 1;

    sniffSocket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (sniffSocket == INVALID_SOCKET) return 1;

    gethostname(hostname, sizeof(hostname));
    local = gethostbyname(hostname);
    struct in_addr addr;
    memcpy(&addr, local->h_addr_list[0], sizeof(struct in_addr));
    std::cout << "[*] Monitoring SMB (0x32 & 0x33) on: " << inet_ntoa(addr) << std::endl;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = addr.s_addr;
    dest.sin_port = 0;

    if (bind(sniffSocket, (struct sockaddr*)&dest, sizeof(dest)) == SOCKET_ERROR) {
        return 1;
    }

    DWORD dwBufferIn = 1; 
    DWORD dwBufferOut;
    WSAIoctl(sniffSocket, SIO_RCVALL, &dwBufferIn, sizeof(dwBufferIn), 0, 0, &dwBufferOut, 0, 0);

    while (true) {
        int bytesRead = recv(sniffSocket, buffer, MAX_PACKET_SIZE, 0);
        
        if (bytesRead > 0) {
            IPHeader* ipHeader = (IPHeader*)buffer;
            
            unsigned short ipHeaderLen = (ipHeader->ver_ihl & 0x0F) * 4;
            unsigned char* ipPayload = (unsigned char*)buffer + ipHeaderLen;
            int ipPayloadTotalSize = bytesRead - ipHeaderLen;

            if (ipHeader->destAddr.s_addr == addr.s_addr && ipHeader->protocol == IPPROTO_TCP) {
                TCPHeader* tcpHeader = (TCPHeader*)ipPayload;
                unsigned short tcpHeaderLen = (tcpHeader->data_offset >> 4) * 4;
                
                unsigned char* appData = ipPayload + tcpHeaderLen;
                int appDataSize = ipPayloadTotalSize - tcpHeaderLen;
                
                if (appDataSize > 0) {
                    analyzeSMB(appData, appDataSize, ipHeader->srcAddr);
                }
            }
        }
    }

    delete[] buffer;
    closesocket(sniffSocket);
    WSACleanup();
    return 0;
}