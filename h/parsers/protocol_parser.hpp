#ifndef PROTOCOL_PARSER_HPP
#define PROTOCOL_PARSER_HPP

#include <cstdint>
#include <cstddef>
#include <memory>
#include <unordered_map>

class ProtocolParser {
public:
    virtual ~ProtocolParser() = default;
    
    virtual bool parse(const uint8_t* data, size_t len) = 0;
    virtual void print() const = 0;
    virtual const char* protocol_name() const = 0;
    
    static ProtocolParser* get_parser(uint16_t ethertype);
    
private:
    static std::unordered_map<uint16_t, std::unique_ptr<ProtocolParser>> s_parsers;
    static ProtocolParser* create_parser(uint16_t ethertype);
};

#endif
