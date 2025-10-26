#include <gtest/gtest.h>
#include "parsers/frame.hpp"
#include <cstring>

class FrameParserTest : public ::testing::Test {
protected:
    EthernetFrame frame;
};

TEST_F(FrameParserTest, ValidIpv4Frame) {
    uint8_t data[] = {
        0x88, 0x86, 0x03, 0xFA, 0x52, 0x91,
        0xA4, 0x97, 0xB1, 0x70, 0x18, 0xD7,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x34
    };
    
    ASSERT_TRUE(parse_ethernet_frame(data, sizeof(data), frame));
    EXPECT_EQ(frame.dst_mac, "88:86:03:fa:52:91");
    EXPECT_EQ(frame.src_mac, "a4:97:b1:70:18:d7");
    EXPECT_EQ(frame.ethertype, 0x0800);
    EXPECT_EQ(frame.payload_len, 4);
}

TEST_F(FrameParserTest, ValidArpFrame) {
    uint8_t data[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x08, 0x06,
        0x00, 0x01, 0x08, 0x00
    };
    
    ASSERT_TRUE(parse_ethernet_frame(data, sizeof(data), frame));
    EXPECT_EQ(frame.dst_mac, "ff:ff:ff:ff:ff:ff");
    EXPECT_EQ(frame.ethertype, 0x0806);
}

TEST_F(FrameParserTest, MinimumValidFrame) {
    uint8_t data[14] = {};
    ASSERT_TRUE(parse_ethernet_frame(data, 14, frame));
    EXPECT_EQ(frame.payload_len, 0);
}

TEST_F(FrameParserTest, FrameTooShort13Bytes) {
    uint8_t data[13] = {};
    EXPECT_FALSE(parse_ethernet_frame(data, 13, frame));
}

TEST_F(FrameParserTest, EmptyFrame) {
    EXPECT_FALSE(parse_ethernet_frame(nullptr, 0, frame));
}

TEST_F(FrameParserTest, NullPointerWithValidLength) {
    EXPECT_FALSE(parse_ethernet_frame(nullptr, 100, frame));
}

TEST_F(FrameParserTest, ValidPointerZeroLength) {
    uint8_t data[14];
    EXPECT_FALSE(parse_ethernet_frame(data, 0, frame));
}

TEST_F(FrameParserTest, UnicastDestination) {
    uint8_t data[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // unicast (LSB=0)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    };
    
    ASSERT_TRUE(parse_ethernet_frame(data, sizeof(data), frame));
    EXPECT_EQ(frame.dst_mac[1], '0');  // unicast bit
}

TEST_F(FrameParserTest, MulticastDestination) {
    uint8_t data[] = {
        0x01, 0x00, 0x5E, 0x00, 0x00, 0x01,  // multicast (LSB=1)
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x08, 0x00
    };
    
    ASSERT_TRUE(parse_ethernet_frame(data, sizeof(data), frame));
    EXPECT_EQ(frame.dst_mac, "01:00:5e:00:00:01");
}

TEST_F(FrameParserTest, BroadcastDestination) {
    uint8_t data[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    };
    
    ASSERT_TRUE(parse_ethernet_frame(data, sizeof(data), frame));
    EXPECT_EQ(frame.dst_mac, "ff:ff:ff:ff:ff:ff");
}

TEST_F(FrameParserTest, LocallyAdministeredMac) {
    uint8_t data[] = {
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,  // locally administered
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    };
    
    ASSERT_TRUE(parse_ethernet_frame(data, sizeof(data), frame));
    EXPECT_EQ(frame.dst_mac, "02:00:00:00:00:01");
}

TEST_F(FrameParserTest, Ipv6EtherType) {
    uint8_t data[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x86, 0xDD  // IPv6
    };
    
    ASSERT_TRUE(parse_ethernet_frame(data, sizeof(data), frame));
    EXPECT_EQ(frame.ethertype, 0x86DD);
}

TEST_F(FrameParserTest, VlanTag) {
    uint8_t data[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x81, 0x00,  // VLAN
        0x00, 0x64   // VLAN ID
    };
    
    ASSERT_TRUE(parse_ethernet_frame(data, sizeof(data), frame));
    EXPECT_EQ(frame.ethertype, 0x8100);
    EXPECT_EQ(frame.payload_len, 2);
}

TEST_F(FrameParserTest, MaximumMtuPayload) {
    uint8_t data[1514];  // 14 header + 1500 MTU
    memset(data, 0xAB, sizeof(data));
    data[12] = 0x08; data[13] = 0x00;
    
    ASSERT_TRUE(parse_ethernet_frame(data, sizeof(data), frame));
    EXPECT_EQ(frame.payload_len, 1500);
}

TEST_F(FrameParserTest, JumboFrame) {
    uint8_t data[9014];  // 14 + 9000 jumbo
    memset(data, 0xFF, sizeof(data));
    data[12] = 0x08; data[13] = 0x00;
    
    ASSERT_TRUE(parse_ethernet_frame(data, sizeof(data), frame));
    EXPECT_EQ(frame.payload_len, 9000);
}

TEST_F(FrameParserTest, PayloadPointerValidity) {
    uint8_t data[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0xDE, 0xAD, 0xBE, 0xEF
    };
    
    ASSERT_TRUE(parse_ethernet_frame(data, sizeof(data), frame));
    EXPECT_EQ(frame.payload, data + 14);
    EXPECT_EQ(std::memcmp(frame.payload, "\xDE\xAD\xBE\xEF", 4), 0);
}

TEST_F(FrameParserTest, ManyFramesInSequence) {
    uint8_t data[14];
    memset(data, 0, sizeof(data));
    data[12] = 0x08; data[13] = 0x00;
    
    for (int i = 0; i < 10000; ++i) {
        ASSERT_TRUE(parse_ethernet_frame(data, sizeof(data), frame));
    }
}

TEST_F(FrameParserTest, AlternatingLengths) {
    for (size_t len = 0; len < 100; ++len) {
        uint8_t data[100] = {};
        data[12] = 0x08; data[13] = 0x00;
        
        if (len < 14) {
            EXPECT_FALSE(parse_ethernet_frame(data, len, frame));
        } else {
            ASSERT_TRUE(parse_ethernet_frame(data, len, frame));
            EXPECT_EQ(frame.payload_len, len - 14);
        }
    }
}

TEST_F(FrameParserTest, TcpSynPacket) {
    uint8_t data[] = {
        0x52, 0x54, 0x00, 0x12, 0x34, 0x56,
        0x08, 0x00, 0x27, 0xAB, 0xCD, 0xEF,
        0x08, 0x00,  // IPv4
        0x45, 0x00, 0x00, 0x3C  // TCP SYN start
    };
    
    ASSERT_TRUE(parse_ethernet_frame(data, sizeof(data), frame));
    EXPECT_EQ(frame.ethertype, 0x0800);
    EXPECT_EQ(frame.payload[0], 0x45);
}

TEST_F(FrameParserTest, DnsQueryPacket) {
    uint8_t data[] = {
        0x00, 0x0C, 0x29, 0x12, 0x34, 0x56,
        0x00, 0x50, 0x56, 0xAB, 0xCD, 0xEF,
        0x08, 0x00,
        0x45, 0x00 
    };
    
    ASSERT_TRUE(parse_ethernet_frame(data, sizeof(data), frame));
    EXPECT_GT(frame.payload_len, 0);
}
