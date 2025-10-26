#ifndef FRAME_HPP
#define FRAME_HPP

#include <string>
#include <cstdint>
#include <cstddef>

struct EthernetFrame {
    std::string src_mac;
    std::string dst_mac;
    uint16_t ethertype;
    const uint8_t* payload;
    size_t payload_len;
};

bool parse_ethernet_frame(const uint8_t* data, size_t len, EthernetFrame& frame);

#endif
