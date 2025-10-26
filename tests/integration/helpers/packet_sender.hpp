#pragma once
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <sys/ioctl.h>
#include <vector>
#include <iostream>

class RawPacketSender {
public:
    RawPacketSender(const std::string& interface) : iface(interface), sockfd(-1) {
        // create raw socket
        sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sockfd < 0) {
            std::cerr << "Failed to create raw socket (need sudo)" << std::endl;
            return;
        }

        // get interface index
        ifreq ifr{};
        strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);
        if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
            std::cerr << "Failed to get interface index" << std::endl;
            close(sockfd);
            sockfd = -1;
            return;
        }
        ifindex = ifr.ifr_ifindex;

        std::cout << "RawPacketSender initialized on " << interface << std::endl;
    }

    ~RawPacketSender() {
        if (sockfd >= 0) {
            close(sockfd);
        }
    }

    bool is_valid() const { return sockfd >= 0; }

    // send ARP request packet
    bool send_arp_request(const std::string& src_mac, const std::string& src_ip,
                          const std::string& dst_ip) {
        std::vector<uint8_t> packet;

        // ethernet header
        packet.insert(packet.end(), {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}); // dst mac (broadcast)
        
        // src MAC
        uint8_t mac[6];
        sscanf(src_mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
        packet.insert(packet.end(), mac, mac + 6);
        
        packet.insert(packet.end(), {0x08, 0x06});

        // ARP header
        packet.insert(packet.end(), {0x00, 0x01});
        packet.insert(packet.end(), {0x08, 0x00});
        packet.push_back(0x06);
        packet.push_back(0x04);
        packet.insert(packet.end(), {0x00, 0x01});

        // sender MAC
        packet.insert(packet.end(), mac, mac + 6);

        // sender IP
        uint32_t src_ip_addr;
        inet_pton(AF_INET, src_ip.c_str(), &src_ip_addr);
        packet.push_back((src_ip_addr >> 0) & 0xFF);
        packet.push_back((src_ip_addr >> 8) & 0xFF);
        packet.push_back((src_ip_addr >> 16) & 0xFF);
        packet.push_back((src_ip_addr >> 24) & 0xFF);

        // target MAC (zeros)
        packet.insert(packet.end(), {0x00, 0x00, 0x00, 0x00, 0x00, 0x00});

        // target IP
        uint32_t dst_ip_addr;
        inet_pton(AF_INET, dst_ip.c_str(), &dst_ip_addr);
        packet.push_back((dst_ip_addr >> 0) & 0xFF);
        packet.push_back((dst_ip_addr >> 8) & 0xFF);
        packet.push_back((dst_ip_addr >> 16) & 0xFF);
        packet.push_back((dst_ip_addr >> 24) & 0xFF);

        // send packet
        sockaddr_ll addr{};
        addr.sll_family = AF_PACKET;
        addr.sll_protocol = htons(ETH_P_ALL);
        addr.sll_ifindex = ifindex;
        addr.sll_halen = ETH_ALEN;
        memcpy(addr.sll_addr, mac, 6);

        ssize_t sent = sendto(sockfd, packet.data(), packet.size(), 0,
                              (struct sockaddr*)&addr, sizeof(addr));

        if (sent < 0) {
            std::cerr << "Failed to send packet" << std::endl;
            return false;
        }

        std::cout << "Sent ARP request: " << src_ip << " -> " << dst_ip 
                  << " (" << sent << " bytes)" << std::endl;
        return true;
    }

    // send ICMP Echo request (ping)
    bool send_icmp_ping(const std::string& src_mac, const std::string& dst_mac,
                        const std::string& src_ip, const std::string& dst_ip) {
        std::vector<uint8_t> packet;

        // ethernet header
        uint8_t dmac[6], smac[6];
        sscanf(dst_mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &dmac[0], &dmac[1], &dmac[2], &dmac[3], &dmac[4], &dmac[5]);
        sscanf(src_mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &smac[0], &smac[1], &smac[2], &smac[3], &smac[4], &smac[5]);
        
        packet.insert(packet.end(), dmac, dmac + 6);
        packet.insert(packet.end(), smac, smac + 6);
        packet.insert(packet.end(), {0x08, 0x00});

        // IPv4 header (20 bytes)
        packet.push_back(0x45);
        packet.push_back(0x00);
        packet.push_back(0x00); packet.push_back(0x3c);
        packet.push_back(0x00); packet.push_back(0x00);
        packet.push_back(0x00); packet.push_back(0x00);
        packet.push_back(0x40);
        packet.push_back(0x01);
        packet.push_back(0x00); packet.push_back(0x00);

        // src IP
        uint32_t sip;
        inet_pton(AF_INET, src_ip.c_str(), &sip);
        packet.push_back((sip >> 0) & 0xFF);
        packet.push_back((sip >> 8) & 0xFF);
        packet.push_back((sip >> 16) & 0xFF);
        packet.push_back((sip >> 24) & 0xFF);

        // dst IP
        uint32_t dip;
        inet_pton(AF_INET, dst_ip.c_str(), &dip);
        packet.push_back((dip >> 0) & 0xFF);
        packet.push_back((dip >> 8) & 0xFF);
        packet.push_back((dip >> 16) & 0xFF);
        packet.push_back((dip >> 24) & 0xFF);

        // ICMP header (8 bytes) + data (32 bytes)
        packet.push_back(0x08);
        packet.push_back(0x00);
        packet.push_back(0x00); packet.push_back(0x00);
        packet.push_back(0x00); packet.push_back(0x01);
        packet.push_back(0x00); packet.push_back(0x01);

        // data (32 bytes)
        for (int i = 0; i < 32; i++) {
            packet.push_back(0x41 + (i % 26)); // 'A' to 'Z'
        }

        // send packet
        sockaddr_ll addr{};
        addr.sll_family = AF_PACKET;
        addr.sll_protocol = htons(ETH_P_ALL);
        addr.sll_ifindex = ifindex;
        addr.sll_halen = ETH_ALEN;
        memcpy(addr.sll_addr, smac, 6);

        ssize_t sent = sendto(sockfd, packet.data(), packet.size(), 0,
                              (struct sockaddr*)&addr, sizeof(addr));

        if (sent < 0) {
            std::cerr << "Failed to send ICMP packet" << std::endl;
            return false;
        }

        std::cout << "Sent ICMP ping: " << src_ip << " -> " << dst_ip 
                  << " (" << sent << " bytes)" << std::endl;
        return true;
    }

private:
    std::string iface;
    int sockfd;
    int ifindex;
};
