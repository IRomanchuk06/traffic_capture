// h/capture.hpp
#pragma once
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

class PacketCapturer {
public:
    PacketCapturer() = default;
    ~PacketCapturer();

    bool open(const std::string& iface, bool promisc);

    void run(std::function<void(const uint8_t*, size_t)> callback, std::atomic<bool>& running);

    void close();

    int get_fd() const {
        return m_fd;
    }

private:
    int m_fd = -1;
    int m_ifindex = -1;
    bool m_promisc = false;
    std::string m_iface;
};
