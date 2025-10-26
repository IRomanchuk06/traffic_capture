#include "parsers/frame.hpp"
#include <sstream>
#include <iomanip>

bool parse_ethernet_frame(const uint8_t* data, size_t len, EthernetFrame& frame) {
    if (!data || len < 14) {
        return false;
    }
    
    // dst MAC
    std::ostringstream dst_mac;
    dst_mac << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        if (i > 0) dst_mac << ":";
        dst_mac << std::setw(2) << static_cast<int>(data[i]);
    }
    frame.dst_mac = dst_mac.str();
    
    // src MAC
    std::ostringstream src_mac;
    src_mac << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        if (i > 0) src_mac << ":";
        src_mac << std::setw(2) << static_cast<int>(data[6 + i]);
    }
    frame.src_mac = src_mac.str();
    
    // EtherType
    frame.ethertype = (data[12] << 8) | data[13];
    
    // payload
    frame.payload = data + 14;
    frame.payload_len = len - 14;
    
    return true;
}
