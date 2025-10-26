#include "parsers/protocol_parser.hpp"

#include <linux/if_ether.h>

#include "parsers/L2/arp.hpp"
#include "parsers/L3/ipv4.hpp"

std::unordered_map<uint16_t, std::unique_ptr<ProtocolParser>> ProtocolParser::s_parsers;

ProtocolParser* ProtocolParser::create_parser(uint16_t ethertype) {
    switch (ethertype) {
        case ETH_P_ARP:
            return new ArpParser();
        case ETH_P_IP:
            return new Ipv4Parser();
        default:
            return nullptr;
    }
}

ProtocolParser* ProtocolParser::get_parser(uint16_t ethertype) {
    auto it = s_parsers.find(ethertype);
    if (it != s_parsers.end()) {
        return it->second.get();
    }

    ProtocolParser* parser = create_parser(ethertype);
    if (parser) {
        s_parsers[ethertype] = std::unique_ptr<ProtocolParser>(parser);
        return parser;
    }

    return nullptr;
}
