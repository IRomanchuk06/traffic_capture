#ifndef IPV4_HPP
#define IPV4_HPP

#include <cstdint>
#include <string>

#include "parsers/protocol_parser.hpp"

struct Ipv4Packet {
    uint8_t version;
    uint8_t header_length;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    std::string src_ip;
    std::string dst_ip;
};

class Ipv4Parser : public ProtocolParser {
public:
    bool parse(const uint8_t* data, size_t len) override;
    void print() const override;
    const char* protocol_name() const override {
        return "IPv4";
    }

private:
    Ipv4Packet m_packet;
    const char* get_protocol_name(uint8_t protocol) const;
};

#endif
