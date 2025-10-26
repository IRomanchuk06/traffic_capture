#include <gtest/gtest.h>
#include "parsers/L2/arp.hpp"
#include <cstring>

class ArpParserTest : public ::testing::Test {
protected:
    ArpParser parser;
};

TEST_F(ArpParserTest, ValidArpRequest) {
    uint8_t data[] = {
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        192, 168, 1, 100,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        192, 168, 1, 1
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(ArpParserTest, ValidArpReply) {
    uint8_t data[] = {
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        10, 0, 0, 1,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        10, 0, 0, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(ArpParserTest, ArpGratuitous) {
    uint8_t data[] = {
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        192, 168, 1, 100,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        192, 168, 1, 100  // same target IP
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(ArpParserTest, ArpProbe) {
    uint8_t data[] = {
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0, 0, 0, 0,  // probe: sender IP is 0.0.0.0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        192, 168, 1, 1
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(ArpParserTest, PacketTooShort27Bytes) {
    uint8_t data[27];
    memset(data, 0, sizeof(data));
    EXPECT_FALSE(parser.parse(data, sizeof(data)));
}

TEST_F(ArpParserTest, MinimumValidSize28Bytes) {
    uint8_t data[28];
    memset(data, 0, sizeof(data));
    data[0] = 0x00; data[1] = 0x01;
    data[2] = 0x08; data[3] = 0x00;
    data[4] = 0x06; data[5] = 0x04;
    data[6] = 0x00; data[7] = 0x01;
    
    ASSERT_TRUE(parser.parse(data, 28));
}

TEST_F(ArpParserTest, NullPointer) {
    EXPECT_FALSE(parser.parse(nullptr, 28));
}

TEST_F(ArpParserTest, ZeroLength) {
    uint8_t data[28];
    EXPECT_FALSE(parser.parse(data, 0));
}

TEST_F(ArpParserTest, BroadcastSenderMac) {
    uint8_t data[] = {
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // broadcast sender
        192, 168, 0, 1,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        192, 168, 0, 255
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(ArpParserTest, UnknownTargetMac) {
    uint8_t data[] = {
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        192, 168, 1, 1,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // unknown target MAC (typical for request)
        192, 168, 1, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(ArpParserTest, AllZeroMacAndIp) {
    uint8_t data[28];
    memset(data, 0, sizeof(data));
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(ArpParserTest, AllMaxMacAndIp) {
    uint8_t data[] = {
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        255, 255, 255, 255,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        255, 255, 255, 255
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(ArpParserTest, NonStandardHardwareType) {
    uint8_t data[] = {
        0xFF, 0xFF,  // unknown hardware type
        0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        192, 168, 1, 1,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        192, 168, 1, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(ArpParserTest, NonIpv4ProtocolType) {
    uint8_t data[] = {
        0x00, 0x01, 0x86, 0xDD,  // IPv6
        0x06, 0x04, 0x00, 0x01,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        192, 168, 1, 1,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        192, 168, 1, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(ArpParserTest, InvalidOpcodeValue) {
    uint8_t data[] = {
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0xFF,  // invalid opcode
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        192, 168, 1, 1,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        192, 168, 1, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(ArpParserTest, NonStandardHwAddrLen) {
    uint8_t data[] = {
        0x00, 0x01, 0x08, 0x00, 0x20, 0x04,  // HW len = 32
        0x00, 0x01,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        192, 168, 1, 1,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        192, 168, 1, 2
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(ArpParserTest, PrivateNetworkClass_A) {
    uint8_t data[] = {
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        10, 0, 0, 1,  // 10.0.0.0/8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        10, 255, 255, 255
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(ArpParserTest, PrivateNetworkClass_B) {
    uint8_t data[] = {
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        172, 16, 0, 1,  // 172.16.0.0/12
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        172, 31, 255, 255
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(ArpParserTest, PrivateNetworkClass_C) {
    uint8_t data[] = {
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        192, 168, 0, 1,  // 192.168.0.0/16
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        192, 168, 255, 255
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(ArpParserTest, LinkLocalAddress) {
    uint8_t data[] = {
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        169, 254, 0, 1,  // 169.254.0.0/16 link-local
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        169, 254, 255, 255
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(ArpParserTest, LoopbackAddress) {
    uint8_t data[] = {
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        127, 0, 0, 1,  // loopback
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        127, 255, 255, 255
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(ArpParserTest, MulticastAddress) {
    uint8_t data[] = {
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        224, 0, 0, 1,  // multicast 224.0.0.0/4
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        239, 255, 255, 255
    };
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(ArpParserTest, LargerPacketWithExtraData) {
    uint8_t data[100];
    memset(data, 0xFF, sizeof(data));
    data[0] = 0x00; data[1] = 0x01;
    data[2] = 0x08; data[3] = 0x00;
    data[4] = 0x06; data[5] = 0x04;
    data[6] = 0x00; data[7] = 0x01;
    memset(data + 8, 0xAA, 6);
    data[14] = 192; data[15] = 168; data[16] = 1; data[17] = 1;
    memset(data + 18, 0xBB, 6);
    data[24] = 192; data[25] = 168; data[26] = 1; data[27] = 2;
    
    ASSERT_TRUE(parser.parse(data, sizeof(data)));
}

TEST_F(ArpParserTest, ManyArpPacketsInSequence) {
    uint8_t data[] = {
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        192, 168, 1, 100,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        192, 168, 1, 1
    };
    
    for (int i = 0; i < 1000; ++i) {
        ASSERT_TRUE(parser.parse(data, sizeof(data)));
    }
}

TEST_F(ArpParserTest, ProtocolNameCheck) {
    EXPECT_STREQ(parser.protocol_name(), "ARP");
}
