#include <gtest/gtest.h>

#include <cstring>
#include <filesystem>
#include <fstream>

#include "export/pcap.hpp"

namespace fs = std::filesystem;

class PcapWriterTest : public ::testing::Test {
protected:
    PcapWriter writer;
    std::string test_dir = "/tmp/pcap_test";

    void SetUp() override {
        fs::create_directories(test_dir);
    }

    void TearDown() override {
        fs::remove_all(test_dir);
    }

    std::string get_test_file(const std::string& name) {
        return test_dir + "/" + name;
    }

    bool file_exists(const std::string& path) {
        return fs::exists(path);
    }

    size_t file_size(const std::string& path) {
        return fs::file_size(path);
    }

    bool check_pcap_magic(const std::string& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file)
            return false;

        uint32_t magic;
        file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
        return magic == 0xa1b2c3d4;
    }
};

TEST_F(PcapWriterTest, OpenValidFile) {
    std::string path = get_test_file("test.pcap");
    ASSERT_TRUE(writer.open(path));
    EXPECT_TRUE(file_exists(path));
    EXPECT_TRUE(writer.is_open());
    writer.close();
}

TEST_F(PcapWriterTest, AutoAddPcapExtension) {
    std::string path = get_test_file("test");
    ASSERT_TRUE(writer.open(path));
    EXPECT_TRUE(file_exists(get_test_file("test.pcap")));
    writer.close();
}

TEST_F(PcapWriterTest, DontDoubleAddExtension) {
    std::string path = get_test_file("test.pcap");
    ASSERT_TRUE(writer.open(path));
    EXPECT_TRUE(file_exists(get_test_file("test.pcap")));
    EXPECT_FALSE(file_exists(get_test_file("test.pcap.pcap")));
    writer.close();
}

TEST_F(PcapWriterTest, GlobalHeaderWritten) {
    std::string path = get_test_file("header_test.pcap");
    ASSERT_TRUE(writer.open(path));
    writer.close();

    EXPECT_GE(file_size(path), 24);  // Global header is 24 bytes
    EXPECT_TRUE(check_pcap_magic(path));
}

TEST_F(PcapWriterTest, WriteOnePacket) {
    std::string path = get_test_file("one_packet.pcap");
    ASSERT_TRUE(writer.open(path));

    uint8_t packet[] = {0x45, 0x00, 0x00, 0x3C};
    writer.write_packet(packet, sizeof(packet));
    writer.close();

    size_t expected_size = 24 + 16 + 4;  // global header + packet header + packet
    EXPECT_EQ(file_size(path), expected_size);
}

TEST_F(PcapWriterTest, WriteManyPackets) {
    std::string path = get_test_file("many_packets.pcap");
    ASSERT_TRUE(writer.open(path));

    uint8_t packet[] = {0x45, 0x00, 0x00, 0x3C, 0x00, 0x00};

    for (int i = 0; i < 100; ++i) {
        writer.write_packet(packet, sizeof(packet));
    }
    writer.close();

    size_t expected_size = 24 + (100 * (16 + sizeof(packet)));
    EXPECT_EQ(file_size(path), expected_size);
}

TEST_F(PcapWriterTest, WriteEmptyPacket) {
    std::string path = get_test_file("empty_packet.pcap");
    ASSERT_TRUE(writer.open(path));

    uint8_t empty_packet[] = {};
    writer.write_packet(empty_packet, 0);
    writer.close();

    size_t expected_size = 24 + 16;  // global header + packet header (no data)
    EXPECT_EQ(file_size(path), expected_size);
}

TEST_F(PcapWriterTest, WriteSmallPacket) {
    std::string path = get_test_file("small_packet.pcap");
    ASSERT_TRUE(writer.open(path));

    uint8_t packet[] = {0xAA};
    writer.write_packet(packet, 1);
    writer.close();

    size_t expected_size = 24 + 16 + 1;
    EXPECT_EQ(file_size(path), expected_size);
}

TEST_F(PcapWriterTest, WriteLargePacket) {
    std::string path = get_test_file("large_packet.pcap");
    ASSERT_TRUE(writer.open(path));

    uint8_t large_packet[65535];
    memset(large_packet, 0xFF, sizeof(large_packet));
    writer.write_packet(large_packet, sizeof(large_packet));
    writer.close();

    size_t expected_size = 24 + 16 + 65535;
    EXPECT_EQ(file_size(path), expected_size);
}

TEST_F(PcapWriterTest, WriteMtuSizedPacket) {
    std::string path = get_test_file("mtu_packet.pcap");
    ASSERT_TRUE(writer.open(path));

    uint8_t packet[1500];  // Standard MTU
    memset(packet, 0x42, sizeof(packet));
    writer.write_packet(packet, sizeof(packet));
    writer.close();

    size_t expected_size = 24 + 16 + 1500;
    EXPECT_EQ(file_size(path), expected_size);
}

TEST_F(PcapWriterTest, WriteJumboPacket) {
    std::string path = get_test_file("jumbo_packet.pcap");
    ASSERT_TRUE(writer.open(path));

    uint8_t packet[9000];  // Jumbo frame
    memset(packet, 0xCC, sizeof(packet));
    writer.write_packet(packet, sizeof(packet));
    writer.close();

    size_t expected_size = 24 + 16 + 9000;
    EXPECT_EQ(file_size(path), expected_size);
}

TEST_F(PcapWriterTest, PacketHeaderSize) {
    std::string path = get_test_file("packet_header.pcap");
    ASSERT_TRUE(writer.open(path));

    uint8_t packet[] = {0x00, 0x01, 0x02, 0x03};
    writer.write_packet(packet, sizeof(packet));
    writer.close();

    std::ifstream file(path, std::ios::binary);
    file.seekg(24 + 4);  // Skip global header and ts_sec, read ts_usec

    uint32_t ts_usec;
    file.read(reinterpret_cast<char*>(&ts_usec), 4);
    EXPECT_GE(ts_usec, 0);
    EXPECT_LT(ts_usec, 1000000);  // Must be < 1 second
}

TEST_F(PcapWriterTest, IsOpenAfterOpen) {
    std::string path = get_test_file("is_open.pcap");
    EXPECT_FALSE(writer.is_open());

    writer.open(path);
    EXPECT_TRUE(writer.is_open());

    writer.close();
    EXPECT_FALSE(writer.is_open());
}

TEST_F(PcapWriterTest, WriteWithoutOpen) {
    uint8_t packet[] = {0xFF, 0xFF};
    writer.write_packet(packet, sizeof(packet));  // Should not crash
    EXPECT_FALSE(writer.is_open());
}

TEST_F(PcapWriterTest, CloseWithoutOpen) {
    writer.close();  // Should not crash
    EXPECT_FALSE(writer.is_open());
}

TEST_F(PcapWriterTest, DestructorClosesFile) {
    std::string path = get_test_file("destructor.pcap");
    {
        PcapWriter temp_writer;
        temp_writer.open(path);
        uint8_t packet[] = {0xAA};
        temp_writer.write_packet(packet, 1);
    }  // Destructor called here

    EXPECT_TRUE(file_exists(path));
}

TEST_F(PcapWriterTest, TruncateExistingFile) {
    std::string path = get_test_file("truncate.pcap");

    // Create initial file
    std::ofstream initial(path, std::ios::binary);
    initial.write("JUNK", 4);
    initial.close();

    // Open should truncate
    ASSERT_TRUE(writer.open(path));
    writer.close();

    // Should only have global header
    EXPECT_EQ(file_size(path), 24);
}

TEST_F(PcapWriterTest, OverwriteAllPackets) {
    std::string path = get_test_file("overwrite.pcap");

    ASSERT_TRUE(writer.open(path));
    uint8_t packet1[] = {0x11, 0x22};
    writer.write_packet(packet1, sizeof(packet1));
    writer.close();

    size_t size_after_first = file_size(path);

    ASSERT_TRUE(writer.open(path));  // Truncate again
    uint8_t packet2[] = {0xAA, 0xBB};
    writer.write_packet(packet2, sizeof(packet2));
    writer.close();

    EXPECT_EQ(file_size(path), size_after_first);  // Same size
}

TEST_F(PcapWriterTest, WriteAlternatingPackets) {
    std::string path = get_test_file("alternating.pcap");
    ASSERT_TRUE(writer.open(path));

    uint8_t small[] = {0x01};
    uint8_t medium[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    uint8_t large[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A};

    for (int i = 0; i < 10; ++i) {
        writer.write_packet(small, sizeof(small));
        writer.write_packet(medium, sizeof(medium));
        writer.write_packet(large, sizeof(large));
    }
    writer.close();

    size_t expected = 24 + (30 * 16) + (10 * 1) + (10 * 5) + (10 * 10);
    EXPECT_EQ(file_size(path), expected);
}

TEST_F(PcapWriterTest, NoWriteAfterClose) {
    std::string path = get_test_file("no_write_after_close.pcap");
    ASSERT_TRUE(writer.open(path));

    uint8_t packet1[] = {0xAA};
    writer.write_packet(packet1, sizeof(packet1));

    size_t size_before = file_size(path);

    writer.close();

    uint8_t packet2[] = {0xBB, 0xCC};
    writer.write_packet(packet2, sizeof(packet2));  // Should not write

    EXPECT_EQ(file_size(path), size_before);
}

TEST_F(PcapWriterTest, FilePermissionsReadable) {
    std::string path = get_test_file("readable.pcap");
    ASSERT_TRUE(writer.open(path));
    uint8_t packet[] = {0x55};
    writer.write_packet(packet, sizeof(packet));
    writer.close();

    std::ifstream file(path, std::ios::binary);
    EXPECT_TRUE(file.is_open());
    file.close();
}

TEST_F(PcapWriterTest, PacketDataIntegrity) {
    std::string path = get_test_file("integrity.pcap");
    ASSERT_TRUE(writer.open(path));

    uint8_t original[] = {0xDE, 0xAD, 0xBE, 0xEF};
    writer.write_packet(original, sizeof(original));
    writer.close();

    std::ifstream file(path, std::ios::binary);
    file.seekg(24 + 16);  // Skip to packet data

    uint8_t read_data[4];
    file.read(reinterpret_cast<char*>(read_data), sizeof(read_data));

    for (int i = 0; i < 4; ++i) {
        EXPECT_EQ(read_data[i], original[i]);
    }
}

TEST_F(PcapWriterTest, ConsecutiveOpenClose) {
    std::string path = get_test_file("consecutive.pcap");

    for (int i = 0; i < 5; ++i) {
        ASSERT_TRUE(writer.open(path));
        uint8_t packet[] = {static_cast<uint8_t>(i)};
        writer.write_packet(packet, sizeof(packet));
        writer.close();
    }

    EXPECT_TRUE(file_exists(path));
}
