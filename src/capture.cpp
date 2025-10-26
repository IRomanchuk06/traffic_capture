#include "capture.hpp"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstring>
#include <iostream>
#include <stdexcept>

PacketCapturer::~PacketCapturer() {
    close();
}

bool PacketCapturer::open(const std::string& iface, bool promisc) {
    m_iface = iface;
    m_promisc = promisc;

    m_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (m_fd < 0) {
        std::cerr << "[!] socket(AF_PACKET) failed: " << strerror(errno) << "\n";
        return false;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);

    // get system interface indx
    if (ioctl(m_fd, SIOCGIFINDEX, &ifr) < 0) {
        std::cerr << "[!] ioctl(SIOCGIFINDEX) failed for " << iface << ": " << strerror(errno)
                  << "\n";
        ::close(m_fd);
        m_fd = -1;
        return false;
    }
    m_ifindex = ifr.ifr_ifindex;

    struct sockaddr_ll sll;
    std::memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = m_ifindex;

    if (bind(m_fd, reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll)) < 0) {
        std::cerr << "[!] bind() failed: " << strerror(errno) << "\n";
        ::close(m_fd);
        m_fd = -1;
        return false;
    }

    if (promisc) {
        struct packet_mreq mreq;
        std::memset(&mreq, 0, sizeof(mreq));
        mreq.mr_ifindex = m_ifindex;
        mreq.mr_type = PACKET_MR_PROMISC;

        if (setsockopt(m_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            std::cerr << "[!] Warning: failed to enable promiscuous mode: " << strerror(errno)
                      << "\n";
        }
    }

    return true;
}

void PacketCapturer::run(const std::function<void(const uint8_t*, size_t)>& callback,
                         std::atomic<bool>& running) {
    if (m_fd < 0) {
        throw std::runtime_error("Socket not opened. Call open() first.");
    }

    const size_t BUFFER_SIZE = 65536;
    uint8_t buffer[BUFFER_SIZE];

    while (running.load()) {
        ssize_t len = recv(m_fd, buffer, BUFFER_SIZE, 0);

        if (len < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error(std::string("recv() failed: ") + strerror(errno));
        }

        if (len == 0) {
            continue;
        }

        callback(buffer, static_cast<size_t>(len));
    }
}

void PacketCapturer::close() {
    if (m_fd >= 0) {
        if (m_promisc) {
            struct packet_mreq mreq;
            std::memset(&mreq, 0, sizeof(mreq));
            mreq.mr_ifindex = m_ifindex;
            mreq.mr_type = PACKET_MR_PROMISC;

            setsockopt(m_fd, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
        }

        ::close(m_fd);
        m_fd = -1;
    }
}
