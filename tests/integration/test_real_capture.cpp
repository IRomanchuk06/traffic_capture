#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>

#include "capture.hpp"
#include "helpers/packet_sender.hpp"
#include "helpers/veth_setup.hpp"
#include "parsers/frame.hpp"
#include "parsers/L2/arp.hpp"

class VethCaptureTest : public ::testing::Test {
protected:
    std::atomic<int> packets_received{0};
    std::atomic<bool> capture_running{false};
};

TEST_F(VethCaptureTest, CaptureArpOnVethPair) {
    if (geteuid() != 0) {
        GTEST_SKIP() << "Requires root privileges";
    }

    VethPair veth("veth_test0", "veth_test1");
    if (!veth.is_created()) {
        GTEST_SKIP() << "Failed to create veth pair";
    }

    capture_running = true;
    std::thread capture_thread([this, &veth]() {
        try {
            PacketCapturer capturer;
            if (!capturer.open(veth.get_veth1(), false)) {
                return;
            }

            capturer.run([this](const uint8_t* data, size_t len) { packets_received++; },
                         capture_running);
        } catch (...) {
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    RawPacketSender sender(veth.get_veth2());
    ASSERT_TRUE(sender.is_valid());

    bool sent = sender.send_arp_request("aa:bb:cc:dd:ee:ff", "10.0.0.1", "10.0.0.2");
    ASSERT_TRUE(sent);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    capture_running = false;
    capture_thread.join();

    EXPECT_GT(packets_received.load(), 0);
}

TEST_F(VethCaptureTest, CaptureIcmpOnVethPair) {
    if (geteuid() != 0) {
        GTEST_SKIP() << "Requires root privileges";
    }

    VethPair veth("veth_icmp0", "veth_icmp1");
    if (!veth.is_created()) {
        GTEST_SKIP() << "Failed to create veth pair";
    }

    bool ipv4_captured = false;
    capture_running = true;

    std::thread capture_thread([this, &veth, &ipv4_captured]() {
        try {
            PacketCapturer capturer;
            if (!capturer.open(veth.get_veth1(), false)) {
                return;
            }

            capturer.run(
                [this, &ipv4_captured](const uint8_t* data, size_t len) {
                    packets_received++;
                    EthernetFrame frame;
                    if (parse_ethernet_frame(data, len, frame) && frame.ethertype == 0x0800) {
                        ipv4_captured = true;
                    }
                },
                capture_running);
        } catch (...) {
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    RawPacketSender sender(veth.get_veth2());
    ASSERT_TRUE(sender.is_valid());

    bool sent =
        sender.send_icmp_ping("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", "10.0.0.1", "10.0.0.2");
    ASSERT_TRUE(sent);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    capture_running = false;
    capture_thread.join();

    EXPECT_TRUE(ipv4_captured);
}

TEST_F(VethCaptureTest, MultiplePacketsOnVeth) {
    if (geteuid() != 0) {
        GTEST_SKIP() << "Requires root privileges";
    }

    VethPair veth("veth_multi0", "veth_multi1");
    if (!veth.is_created()) {
        GTEST_SKIP() << "Failed to create veth pair";
    }

    capture_running = true;
    std::thread capture_thread([this, &veth]() {
        try {
            PacketCapturer capturer;
            if (!capturer.open(veth.get_veth1(), false)) {
                return;
            }

            capturer.run([this](const uint8_t* data, size_t len) { packets_received++; },
                         capture_running);
        } catch (...) {
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    RawPacketSender sender(veth.get_veth2());
    ASSERT_TRUE(sender.is_valid());

    for (int i = 0; i < 5; ++i) {
        sender.send_arp_request("aa:bb:cc:dd:ee:ff", "10.0.0.1", "10.0.0.2");
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));
    capture_running = false;
    capture_thread.join();

    EXPECT_GT(packets_received.load(), 0);
}

TEST_F(VethCaptureTest, VethPairAutomaticCleanup) {
    if (geteuid() != 0) {
        GTEST_SKIP() << "Requires root privileges";
    }

    {
        VethPair veth("veth_cleanup0", "veth_cleanup1");
        EXPECT_TRUE(veth.is_created());
    }

    SUCCEED();
}

TEST_F(VethCaptureTest, CaptureWithPromiscuousMode) {
    if (geteuid() != 0) {
        GTEST_SKIP() << "Requires root privileges";
    }

    VethPair veth("veth_promisc0", "veth_promisc1");
    if (!veth.is_created()) {
        GTEST_SKIP() << "Failed to create veth pair";
    }

    capture_running = true;
    std::thread capture_thread([this, &veth]() {
        try {
            PacketCapturer capturer;
            if (!capturer.open(veth.get_veth1(), true)) {
                return;
            }

            capturer.run([this](const uint8_t* data, size_t len) { packets_received++; },
                         capture_running);
        } catch (...) {
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    RawPacketSender sender(veth.get_veth2());
    ASSERT_TRUE(sender.is_valid());

    bool sent = sender.send_arp_request("aa:bb:cc:dd:ee:ff", "10.0.0.1", "10.0.0.2");
    ASSERT_TRUE(sent);

    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    capture_running = false;
    capture_thread.join();

    EXPECT_GT(packets_received.load(), 0);
}
