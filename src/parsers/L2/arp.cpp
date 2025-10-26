#include "parsers/L2/arp.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <arpa/inet.h>
#include <linux/if_ether.h>

bool ArpParser::parse(const uint8_t* data, size_t len) {
    if(!data || len < 28) {
        return false;
    }
    
    // ARP header
    m_packet.hw_type = (data[0] << 8) | data[1];
    m_packet.proto_type = (data[2] << 8) | data[3];
    m_packet.hw_addr_len = data[4];
    m_packet.proto_addr_len = data[5];
    m_packet.opcode = (data[6] << 8) | data[7];
    
    // sender MAC (8-13)
    std::ostringstream sender_mac;
    sender_mac << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        if (i > 0) sender_mac << ":";
        sender_mac << std::setw(2) << static_cast<int>(data[8 + i]);
    }
    m_packet.sender_mac = sender_mac.str();
    
    // sender IP (14-17)
    char ip_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, data + 14, ip_buf, INET_ADDRSTRLEN);
    m_packet.sender_ip = ip_buf;
    
    // target MAC (18-23)
    std::ostringstream target_mac;
    target_mac << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        if (i > 0) target_mac << ":";
        target_mac << std::setw(2) << static_cast<int>(data[18 + i]);
    }
    m_packet.target_mac = target_mac.str();
    
    // target IP (24-27)
    inet_ntop(AF_INET, data + 24, ip_buf, INET_ADDRSTRLEN);
    m_packet.target_ip = ip_buf;
    
    return true;
}

void ArpParser::print() const {
    std::cout << "  Hardware Type: " << m_packet.hw_type 
              << (m_packet.hw_type == 1 ? " (Ethernet)" : "") << "\n";
    std::cout << "  Protocol Type: 0x" << std::hex << m_packet.proto_type << std::dec
              << (m_packet.proto_type == ETH_P_IP ? " (IPv4)" : "") << "\n";
    std::cout << "  Opcode: " << m_packet.opcode 
              << (m_packet.opcode == 1 ? " (Request)" : m_packet.opcode == 2 ? " (Reply)" : " (Unknown)") << "\n";
    std::cout << "  Sender MAC: " << m_packet.sender_mac << "\n";
    std::cout << "  Sender IP:  " << m_packet.sender_ip << "\n";
    std::cout << "  Target MAC: " << m_packet.target_mac << "\n";
    std::cout << "  Target IP:  " << m_packet.target_ip << "\n";
}
