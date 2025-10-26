#include "export/pcap.hpp"

#include <chrono>
#include <cstring>
#include <iostream>

PcapWriter::~PcapWriter() {
    close();
}

bool PcapWriter::open(const std::string& filename) {
    std::string output_filename = filename;

    if (output_filename.size() < 5 ||
        output_filename.substr(output_filename.size() - 5) != ".pcap") {
        output_filename += ".pcap";
    }

    m_file.open(output_filename, std::ios::binary | std::ios::trunc);
    if (!m_file.is_open()) {
        std::cerr << "[!] Failed to open PCAP file: " << output_filename << "\n";
        return false;
    }

    write_global_header();
    return true;
}

void PcapWriter::write_global_header() {
    PcapGlobalHeader header;
    header.magic_number = 0xa1b2c3d4;
    header.version_major = 2;
    header.version_minor = 4;
    header.thiszone = 0;
    header.sigfigs = 0;
    header.snaplen = 65535;
    header.network = 1;

    m_file.write(reinterpret_cast<const char*>(&header), sizeof(header));
}

void PcapWriter::write_packet_header(uint32_t len) {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration - seconds);

    PcapPacketHeader header;
    header.ts_sec = static_cast<uint32_t>(seconds.count());
    header.ts_usec = static_cast<uint32_t>(microseconds.count());
    header.incl_len = len;
    header.orig_len = len;

    m_file.write(reinterpret_cast<const char*>(&header), sizeof(header));
}

void PcapWriter::write_packet(const uint8_t* data, size_t len) {
    if (!m_file.is_open()) {
        return;
    }

    write_packet_header(static_cast<uint32_t>(len));
    m_file.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
    m_file.flush();
}

void PcapWriter::close() {
    if (m_file.is_open()) {
        m_file.close();
    }
}
