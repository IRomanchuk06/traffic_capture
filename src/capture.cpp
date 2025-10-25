#include "capture.hpp"

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <stdexcept>
#include <iostream>
#include <csignal>

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
        std::cerr << "[!] ioctl(SIOCGIFINDEX) failed for " << iface 
                  << ": " << strerror(errno) << "\n";
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
        
        if (setsockopt(m_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, 
                       &mreq, sizeof(mreq)) < 0) {
            std::cerr << "[!] Warning: failed to enable promiscuous mode: " 
                      << strerror(errno) << "\n";
        }
    }
    
    return true;
}

void PacketCapturer::run(std::function<void(const uint8_t*, size_t)> callback,
                         std::atomic<bool>& running) {
}

void PacketCapturer::close() {
    
}
