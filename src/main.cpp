#include <iostream>
#include <atomic>
#include <csignal>
#include <cstring>

#include "capture.hpp"
#include "cli.hpp"

std::atomic<bool> g_running{true};

void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        std::cerr << "\n[*] Caught signal " << signum << ", shutting down...\n";
        g_running.store(false);
    }
}

void on_frame_captured(const uint8_t* data, size_t len, const CliOptions& opts) {
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
    
    PacketCapturer capturer;
    if (!capturer.open(opts.interface, opts.promiscuous)) {
        std::cerr << "[!] Failed to open capture on " << opts.interface << "\n";
        return 1;
    }
    
    if (!opts.bpf_filter.empty()) {
        // filter engine
    }
    
    try {
        capturer.run([&opts](const uint8_t* data, size_t len) {
            on_frame_captured(data, len, opts);
        }, g_running);
    } catch (const std::exception& e) {
        std::cerr << "[!] Capture error: " << e.what() << "\n";
        capturer.close();
        return 1;
    }
    
    capturer.close();
    std::cout << "\n[*] Capture stopped\n";
    
    return 0;
}
