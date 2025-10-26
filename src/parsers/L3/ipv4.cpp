#include "parsers/L3/ipv4.hpp"
#include <iostream>
#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>

bool Ipv4Parser::parse(const uint8_t* data, size_t len) {
    if (len < 20) {
        return false;
    }
    
    // version and header length
    m_packet.version = (data[0] >> 4) & 0x0F;
    m_packet.header_length = (data[0] & 0x0F) * 4;
    
    if (m_packet.version != 4) {
        return false;
    }
    
    m_packet.tos = data[1];
    m_packet.total_length = (data[2] << 8) | data[3];
    m_packet.identification = (data[4] << 8) | data[5];
    m_packet.flags_offset = (data[6] << 8) | data[7];
    m_packet.ttl = data[8];
    m_packet.protocol = data[9];
    m_packet.checksum = (data[10] << 8) | data[11];
    
    // src IP
    char ip_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, data + 12, ip_buf, INET_ADDRSTRLEN);
    m_packet.src_ip = ip_buf;
    
    // dst IP
    inet_ntop(AF_INET, data + 16, ip_buf, INET_ADDRSTRLEN);
    m_packet.dst_ip = ip_buf;
    
    return true;
}

void Ipv4Parser::print() const {
    std::cout << "  Version: " << static_cast<int>(m_packet.version) << "\n";
    std::cout << "  Header Length: " << static_cast<int>(m_packet.header_length) << " bytes\n";
    std::cout << "  Total Length: " << m_packet.total_length << " bytes\n";
    std::cout << "  TTL: " << static_cast<int>(m_packet.ttl) << "\n";
    std::cout << "  Protocol: " << static_cast<int>(m_packet.protocol) 
              << " (" << get_protocol_name(m_packet.protocol) << ")\n";
    std::cout << "  Source IP: " << m_packet.src_ip << "\n";
    std::cout << "  Destination IP: " << m_packet.dst_ip << "\n";
}

const char* Ipv4Parser::get_protocol_name(uint8_t protocol) const {
    switch (protocol) {
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        case IPPROTO_IPV6: return "IPv6";
        default: return "Unknown";
    }
}