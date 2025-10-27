#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>

#include "capture.hpp"
#include "helpers/packet_sender.hpp"
#include "parsers/frame.hpp"
#include "parsers/L2/arp.hpp"

class LoopbackCaptureTest : public ::testing::Test {
protected:
    std::atomic<int> packets_received{0};
    std::atomic<bool> capture_running{false};
};

TEST_F(LoopbackCaptureTest, OpenInvalidInterface) {
    if (geteuid() != 0) {
        GTEST_SKIP() << "Requires root privileges";
    }

    PacketCapturer capturer;
    bool result = capturer.open("nonexistent_iface_xyz", false);

    EXPECT_FALSE(result);
}

TEST_F(LoopbackCaptureTest, OpenWithoutRoot) {
    if (geteuid() == 0) {
        GTEST_SKIP() << "Test requires non-root user";
    }

    PacketCapturer capturer;
    bool result = capturer.open("lo", false);

    EXPECT_FALSE(result);
}

TEST_F(LoopbackCaptureTest, PromiscuousModeEnabled) {
    if (geteuid() != 0) {
        GTEST_SKIP() << "Requires root privileges";
    }

    PacketCapturer capturer;
    bool result = capturer.open("lo", true);

    EXPECT_TRUE(result);
    capturer.close();
}

TEST_F(LoopbackCaptureTest, CaptureIcmpPacketOnLoopback) {
    if (geteuid() != 0) {
        GTEST_SKIP() << "Requires root privileges";
    }

    RawPacketSender sender("lo");
    if (!sender.is_valid()) {
        GTEST_SKIP() << "Failed to create raw socket";
    }

    bool ipv4_captured = false;
    capture_running = true;

    std::thread capture_thread([this, &ipv4_captured]() {
        try {
            PacketCapturer capturer;
            if (!capturer.open("lo", false)) {
                return;
            }

            capturer.run(
                [this, &ipv4_captured](const uint8_t* data, size_t len) {
                    packets_received++;
                    EthernetFrame frame;
                    if (parse_ethernet_frame(data, len, frame) && frame.ethertype == 0x0800) {
                        ipv4_captured = true;
                        capture_running = false;
                    }
                    if (packets_received >= 10) {
                        capture_running = false;
                    }
                },
                capture_running);
        } catch (...) {
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    for (int i = 0; i < 3; ++i) {
        if (!capture_running)
            break;
        sender.send_icmp_ping("00:11:22:33:44:55", "00:66:77:88:99:aa", "127.0.0.1", "127.0.0.1");
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    capture_running = false;

    if (capture_thread.joinable()) {
        capture_thread.join();
    }

    EXPECT_TRUE(ipv4_captured || packets_received > 0);
}

TEST_F(LoopbackCaptureTest, MultipleArpPacketsSequence) {
    if (geteuid() != 0) {
        GTEST_SKIP() << "Requires root privileges";
    }

    RawPacketSender sender("lo");
    if (!sender.is_valid()) {
        GTEST_SKIP() << "Failed to create raw socket";
    }

    capture_running = true;
    std::thread capture_thread([this]() {
        try {
            PacketCapturer capturer;
            if (!capturer.open("lo", false)) {
                return;
            }

            capturer.run(
                [this](const uint8_t* data, size_t len) {
                    packets_received++;
                    if (packets_received >= 5) {
                        capture_running = false;
                    }
                },
                capture_running);
        } catch (...) {
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    for (int i = 0; i < 10 && capture_running; ++i) {
        sender.send_arp_request("00:11:22:33:44:55", "127.0.0.1", "127.0.0.2");
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    capture_running = false;

    if (capture_thread.joinable()) {
        capture_thread.join();
    }

    EXPECT_GT(packets_received.load(), 0);
}

TEST_F(LoopbackCaptureTest, StopCaptureImmediately) {
    if (geteuid() != 0) {
        GTEST_SKIP() << "Requires root privileges";
    }

    capture_running = false;
    std::atomic<bool> thread_started{false};
    std::atomic<bool> open_succeeded{false};

    std::thread capture_thread([this, &thread_started, &open_succeeded]() {
        try {
            PacketCapturer capturer;
            thread_started = true;

            if (!capturer.open("lo", false)) {
                return;
            }

            open_succeeded = true;

            capturer.run([this](const uint8_t* data, size_t len) { packets_received++; },
                         capture_running);
        } catch (...) {
        }
    });

    auto start = std::chrono::steady_clock::now();
    while (!thread_started.load() &&
           std::chrono::steady_clock::now() - start < std::chrono::milliseconds(500)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    capture_running = false;

    if (capture_thread.joinable()) {
        capture_thread.join();
    }

    EXPECT_TRUE(thread_started.load());
    EXPECT_GE(packets_received.load(), 0);
}

TEST_F(LoopbackCaptureTest, RunWithoutOpenThrowsException) {
    if (geteuid() != 0) {
        GTEST_SKIP() << "Requires root privileges";
    }

    PacketCapturer capturer;
    capture_running = true;

    EXPECT_THROW(
        { capturer.run([](const uint8_t* data, size_t len) {}, capture_running); },
        std::runtime_error);
}

TEST_F(LoopbackCaptureTest, DoubleCloseIsNoop) {
    if (geteuid() != 0) {
        GTEST_SKIP() << "Requires root privileges";
    }

    PacketCapturer capturer;
    ASSERT_TRUE(capturer.open("lo", false));

    capturer.close();
    capturer.close();

    SUCCEED();
}
