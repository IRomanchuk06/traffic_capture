#ifndef ARP_HPP
#define ARP_HPP

#include "parsers/protocol_parser.hpp"
#include <string>
#include <cstdint>

struct ArpPacket {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_addr_len;
    uint8_t proto_addr_len;
    uint16_t opcode;
    std::string sender_mac;
    std::string sender_ip;
    std::string target_mac;
    std::string target_ip;
};

class ArpParser : public ProtocolParser {
public:
    bool parse(const uint8_t* data, size_t len) override;
    void print() const override;
    const char* protocol_name() const override { return "ARP"; }
    
private:
    ArpPacket m_packet;
};

#endif
