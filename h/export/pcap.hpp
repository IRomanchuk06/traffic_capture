#ifndef PCAP_HPP
#define PCAP_HPP

#include <cstdint>
#include <fstream>
#include <string>

class PcapWriter {
public:
    PcapWriter() = default;
    ~PcapWriter();

    bool open(const std::string& filename);
    void write_packet(const uint8_t* data, size_t len);
    void close();

    bool is_open() const {
        return m_file.is_open();
    }

private:
    std::ofstream m_file;

    void write_global_header();
    void write_packet_header(uint32_t len);
};

#pragma pack(push, 1)
struct PcapGlobalHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};
#pragma pack(pop)

#endif
