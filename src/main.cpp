#include <iostream>
#include <atomic>
#include <csignal>
#include <cstring>
#include <iomanip>
#include <chrono>
#include <thread>

#include "capture.hpp"
#include "cli.hpp"
#include "parsers/frame.hpp"
#include "parsers/protocol_parser.hpp"

std::atomic<bool> g_running{true};
std::atomic<int> g_packet_counter{0};

void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        std::cerr << "\n[*] Caught signal " << signum << ", shutting down...\n";
        g_running.store(false);
    }
}

void print_hex_dump(const uint8_t* data, size_t len) {
    std::cout << "\n  HEX Dump:\n";
    for (size_t i = 0; i < len; ++i) {
        if (i % 16 == 0) {
            if (i > 0) std::cout << "\n";
            std::cout << "  " << std::hex << std::setw(4) << std::setfill('0') << i << ":  ";
        }
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]) << " ";
    }
    std::cout << std::dec << "\n";
}

void on_frame_captured(const uint8_t* data, size_t len, const CliOptions& opts) {
    if (len < 14) {
        if (opts.verbose) {
            std::cerr << "[!] Frame too small: " << len << " bytes\n";
        }
        return;
    }
    
    int current_count = g_packet_counter.fetch_add(1) + 1;
    
    EthernetFrame frame;
    if (!parse_ethernet_frame(data, len, frame)) {
        if (opts.verbose) {
            std::cerr << "[!] Failed to parse Ethernet frame\n";
        }
        return;
    }
    
    std::cout << "\n[Packet #" << current_count << "] " << len << " bytes | "
              << frame.src_mac << " -> " << frame.dst_mac << " | "
              << "EtherType: 0x" << std::hex << std::setw(4) << std::setfill('0') 
              << frame.ethertype << std::dec;
    
    if (opts.show_parsed) {
        ProtocolParser* parser = ProtocolParser::get_parser(frame.ethertype);
        
        if (parser) {
            std::cout << " (" << parser->protocol_name() << ")\n";
            
            if (parser->parse(frame.payload, frame.payload_len)) {
                parser->print();
            } else {
                std::cerr << "[!] Failed to parse " << parser->protocol_name() << " packet\n";
            }
        } else {
            std::cout << " (Unknown)\n";
        }
    } else {
        std::cout << "\n";
    }
    
    if (opts.show_hex) {
        print_hex_dump(data, len);
    }

    if (opts.packet_count > 0 && current_count >= opts.packet_count) {
        g_running.store(false);
    }
}

int main(int argc, char** argv) {
    if (geteuid() != 0) {
        std::cerr << "[!] Error: raw sockets require root privileges\n";
        std::cerr << "    Run with sudo or grant CAP_NET_RAW capability\n";
        return 1;
    }
    
    CliOptions opts;
    
    if (!handle_cli(argc, argv, opts)) {
        return 1;
    }
    
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
    
    std::cout << "\n[*] Starting traffic capture on " << opts.interface << "\n";
    std::cout << "[*] Press Ctrl+C to stop\n";
    if (opts.promiscuous) {
        std::cout << "[*] Promiscuous mode enabled\n";
    }
    
    std::cout << "[*] Display mode: ";
    if (opts.show_parsed && opts.show_hex) {
        std::cout << "Parsed + HEX\n";
    } else if (opts.show_parsed) {
        std::cout << "Parsed only\n";
    } else {
        std::cout << "HEX only\n";
    }
    
    if (opts.packet_count > 0) {
        std::cout << "[*] Will capture " << opts.packet_count << " packets\n";
    } else if (opts.capture_duration > 0) {
        std::cout << "[*] Will capture for " << opts.capture_duration << " seconds\n";
    }
    
    PacketCapturer capturer;
    if (!capturer.open(opts.interface, opts.promiscuous)) {
        std::cerr << "[!] Failed to open capture on " << opts.interface << "\n";
        return 1;
    }
    
    std::thread timer_thread;
    if (opts.capture_duration > 0) {
        timer_thread = std::thread([&opts]() {
            std::this_thread::sleep_for(std::chrono::seconds(opts.capture_duration));
            g_running.store(false);
        });
    }
    
    try {
        capturer.run([&opts](const uint8_t* data, size_t len) {
            on_frame_captured(data, len, opts);
        }, g_running);
    } catch (const std::exception& e) {
        std::cerr << "[!] Capture error: " << e.what() << "\n";
        capturer.close();
        if (timer_thread.joinable()) {
            timer_thread.join();
        }
        return 1;
    }
    
    capturer.close();
    
    if (timer_thread.joinable()) {
        timer_thread.join();
    }
    
    std::cout << "\n[*] Capture stopped\n";
    std::cout << "[*] Total packets captured: " << g_packet_counter.load() << "\n";
    
    return 0;
}
