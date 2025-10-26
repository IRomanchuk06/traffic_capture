#include <gtest/gtest.h>
#include "parsers/L3/ipv4.hpp"
#include <cstring>
#include <netinet/in.h>

class Ipv4ParserTest : public ::testing::Test {
protected:
    Ipv4Parser parser;
};

TEST_F(Ipv4ParserTest, ValidIpv4TcpPacket) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 100,  // src IP
        192, 168, 1, 1     // dst IP
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, ValidIpv4UdpPacket) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x50, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00,
        10, 0, 0, 1,
        10, 0, 0, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, ValidIpv4IcmpPacket) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x01, 0x00, 0x00,
        8, 8, 8, 8,
        1, 1, 1, 1
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, MinimumValidHeader20Bytes) {
    uint8_t data[20];
    memset(data, 0, sizeof(data));
    data[0] = 0x45;  // version 4, header length 5
    
    ASSERT_TRUE(parser.parse(data, 20));
}

TEST_F(Ipv4ParserTest, HeaderTooShort19Bytes) {
    uint8_t data[19];
    memset(data, 0, sizeof(data));
    data[0] = 0x45;
    
    EXPECT_FALSE(parser.parse(data, 19));
}

TEST_F(Ipv4ParserTest, NullPointer) {
    EXPECT_FALSE(parser.parse(nullptr, 20));
}

TEST_F(Ipv4ParserTest, ZeroLength) {
    uint8_t data[20];
    EXPECT_FALSE(parser.parse(data, 0));
}

TEST_F(Ipv4ParserTest, InvalidVersion3) {
    uint8_t data[] = {
        0x35, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 1,
        192, 168, 1, 2
    };
    
    EXPECT_FALSE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, InvalidVersion6) {
    uint8_t data[] = {
        0x65, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 1,
        192, 168, 1, 2
    };
    
    EXPECT_FALSE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, MinimumHeaderLength5) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 1,
        192, 168, 1, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, ExtendedHeaderLength15) {
    uint8_t data[] = {
        0x4F, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 1,
        192, 168, 1, 2,
        0x00, 0x00, 0x00, 0x00,  // Options (4 bytes)
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, TosMinimum0) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 1,
        192, 168, 1, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, TosMaximum255) {
    uint8_t data[] = {
        0x45, 0xFF, 0x00, 0x3C, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 1,
        192, 168, 1, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, TotalLengthSmall20) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 1,
        192, 168, 1, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, TotalLengthMaximum65535) {
    uint8_t data[] = {
        0x45, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 1,
        192, 168, 1, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, MoreFragmentBitSet) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x60, 0x00,  // MF flag set
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 1,
        192, 168, 1, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, DontFragmentBitSet) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x40, 0x00,  // DF flag set
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 1,
        192, 168, 1, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, FragmentOffsetNonZero) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x20, 0x64,  // offset 100
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 1,
        192, 168, 1, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, TtlMinimum0) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x40, 0x00,
        0x00, 0x06, 0x00, 0x00,  // TTL = 0
        192, 168, 1, 1,
        192, 168, 1, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, TtlMaximum255) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x40, 0x00,
        0xFF, 0x06, 0x00, 0x00,  // TTL = 255
        192, 168, 1, 1,
        192, 168, 1, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, PrivateNetworkSourceIp) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        10, 0, 0, 1,        // 10.0.0.0/8
        172, 16, 0, 1       // 172.16.0.0/12
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, PrivateNetworkDestIp) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        1, 1, 1, 1,
        192, 168, 0, 1      // 192.168.0.0/16
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, LoopbackAddress) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        127, 0, 0, 1,       // loopback src
        127, 0, 0, 2        // loopback dst
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, MulticastAddress) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 1,
        224, 0, 0, 1        // multicast dest
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, BroadcastAddress) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 1,
        255, 255, 255, 255  // broadcast
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, ZeroSourceAddress) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0, 0, 0, 0,         // src 0.0.0.0
        192, 168, 1, 1
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, PublicIpAddresses) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        8, 8, 8, 8,         // Google DNS
        1, 1, 1, 1          // Cloudflare DNS
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, ProtocolTcp) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x40, 0x00,
        0x40, IPPROTO_TCP, 0x00, 0x00,
        192, 168, 1, 1,
        192, 168, 1, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, ProtocolUdp) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x40, 0x00,
        0x40, IPPROTO_UDP, 0x00, 0x00,
        192, 168, 1, 1,
        192, 168, 1, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, ProtocolIcmp) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x40, 0x00,
        0x40, IPPROTO_ICMP, 0x00, 0x00,
        192, 168, 1, 1,
        192, 168, 1, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, UnknownProtocol) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x40, 0x00,
        0x40, 0xFF, 0x00, 0x00,  // unknown protocol
        192, 168, 1, 1,
        192, 168, 1, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, FragmentedPacketPart1) {
    uint8_t data[] = {
        0x45, 0x00, 0x05, 0xDC, 0x00, 0x00, 0x20, 0x00,  // MF flag, offset 0
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 1,
        192, 168, 1, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, FragmentedPacketPart2) {
    uint8_t data[] = {
        0x45, 0x00, 0x05, 0xDC, 0x00, 0x00, 0x00, 0xB8,  // no MF, offset 184
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 1,
        192, 168, 1, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, LargePacketWith65Kb) {
    uint8_t data[] = {
        0x45, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x40, 0x00,  // 65535 bytes total
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 1,
        192, 168, 1, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(Ipv4ParserTest, ManyIpv4PacketsInSequence) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 1,
        192, 168, 1, 2
    };
    
    for (int i = 0; i < 5000; ++i) {
        ASSERT_TRUE(parser.parse(data, sizeof(data)));
    }
}

TEST_F(Ipv4ParserTest, ProtocolNameCheck) {
    EXPECT_STREQ(parser.protocol_name(), "IPv4");
}
