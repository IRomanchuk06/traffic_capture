#include "cli.hpp"
#include <iostream>
#include <sstream>
#include <vector>
#include <fstream>
#include <cstring>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>

static std::vector<std::string> get_available_interfaces() {
    std::vector<std::string> interfaces;
    
    std::ifstream netdev("/proc/net/dev");
    if (!netdev.is_open()) {
        return interfaces;
    }
    
    std::string line;
    // 2 header lines
    std::getline(netdev, line);
    std::getline(netdev, line);
    
    while (std::getline(netdev, line)) {
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string iface = line.substr(0, colon);
            size_t start = iface.find_first_not_of(" \t");
            if (start != std::string::npos) {
                iface = iface.substr(start);
                interfaces.push_back(iface);
            }
        }
    }
    
    return interfaces;
}

static bool interface_exists(const std::string& iface) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return false;
    }
    
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    
    bool exists = (ioctl(sockfd, SIOCGIFFLAGS, &ifr) >= 0);
    close(sockfd);
    
    return exists;
}

static bool validate_bpf_filter(const std::string& filter) {
    if (filter.empty()) {
        return true; // empty is valid (no filter)
    }
    
    // basic syntax checks
    if (filter.length() > 1024) {
        std::cerr << "[!] Filter too long (max 1024 chars)\n";
        return false;
    }
    
    // balanced parentheses
    int depth = 0;
    for (char c : filter) {
        if (c == '(') depth++;
        if (c == ')') depth--;
        if (depth < 0) {
            std::cerr << "[!] Unbalanced parentheses in filter\n";
            return false;
        }
    }
    if (depth != 0) {
        std::cerr << "[!] Unbalanced parentheses in filter\n";
        return false;
    }
    
    // common keywords (basic validation)
    const std::vector<std::string> valid_keywords = {
        "tcp", "udp", "icmp", "ip", "ip6", "arp", "rarp",
        "port", "host", "net", "src", "dst", "and", "or", "not",
        "ether", "proto", "vlan", "mpls", "pppoe", "pppoes", "pppoed"
    };
    
    // split filter into tokens and check at least one keyword exists
    bool has_keyword = false;
    std::istringstream iss(filter);
    std::string token;
    while (iss >> token) {
        for (const auto& kw : valid_keywords) {
            if (token.find(kw) != std::string::npos) {
                has_keyword = true;
                break;
            }
        }
        if (has_keyword) break;
    }
    
    if (!has_keyword) {
        std::cerr << "[!] Filter doesn't contain recognized BPF keywords\n";
        std::cerr << "    Valid keywords: tcp, udp, icmp, ip, arp, port, host, etc.\n";
        return false;
    }
    
    return true;
}

static void clear_screen() {
    std::cout << "\033[2J\033[H";
}

static int get_choice(int min, int max) {
    std::string input;
    while (true) {
        std::cout << "Choice: ";
        std::getline(std::cin, input);
        
        if (input.empty()) continue;
        
        int choice = std::atoi(input.c_str());
        if (choice >= min && choice <= max) {
            return choice;
        }
        std::cout << "[!] Invalid choice. Enter " << min << "-" << max << "\n";
    }
}

static void print_header(const std::string& title) {
    std::cout << "\n╔═══════════════════════════════════════════╗\n";
    std::cout << "║  " << title;
    for (size_t i = title.length(); i < 41; ++i) std::cout << " ";
    std::cout << "║\n";
    std::cout << "╚═══════════════════════════════════════════╝\n\n";
}

static void setup_interface(CliOptions& opts) {
    clear_screen();
    print_header("Step 1: Select Network Interface");
    
    auto interfaces = get_available_interfaces();
    
    if (interfaces.empty()) {
        std::cout << "[!] No interfaces found. Using default: eth0\n";
        opts.interface = "eth0";
        return;
    }
    
    std::cout << "Available interfaces:\n\n";
    for (size_t i = 0; i < interfaces.size(); ++i) {
        std::cout << "  " << (i + 1) << ") " << interfaces[i] << "\n";
    }
    std::cout << "  0) Enter manually\n\n";
    
    int choice = get_choice(0, interfaces.size());
    
    if (choice == 0) {
        // manual input with validation
        while (true) {
            std::cout << "Enter interface name: ";
            std::string iface_input;
            std::getline(std::cin, iface_input);
            
            size_t start = iface_input.find_first_not_of(" \t");
            size_t end = iface_input.find_last_not_of(" \t");
            if (start != std::string::npos && end != std::string::npos) {
                iface_input = iface_input.substr(start, end - start + 1);
            }
            
            if (iface_input.empty()) {
                std::cout << "[!] Interface name cannot be empty. Try again.\n";
                continue;
            }
            
            if (iface_input.length() > IFNAMSIZ - 1) {
                std::cout << "[!] Interface name too long (max " << (IFNAMSIZ - 1) << " chars)\n";
                continue;
            }
            
            if (!interface_exists(iface_input)) {
                std::cout << "[!] Interface '" << iface_input << "' not found\n";
                std::cout << "    Continue anyway? (y/n): ";
                std::string confirm;
                std::getline(std::cin, confirm);
                if (confirm != "y" && confirm != "Y") {
                    continue;
                }
            }
            
            opts.interface = iface_input;
            break;
        }
    } else {
        opts.interface = interfaces[choice - 1];
    }
    
    std::cout << "\n[+] Selected: " << opts.interface << "\n";
    
    std::cout << "\nEnable promiscuous mode? (y/n): ";
    std::string answer;
    std::getline(std::cin, answer);
    opts.promiscuous = (answer == "y" || answer == "Y" || answer == "yes");
    
    std::cout << "\nPress Enter to continue...";
    std::getline(std::cin, answer);
}

static void setup_capture_limit(CliOptions& opts) {
    clear_screen();
    print_header("Step 2: Capture Duration/Limit");
    
    std::cout << "How to limit capture?\n\n";
    std::cout << "  1) Packet count (e.g., capture 1000 packets)\n";
    std::cout << "  2) Time duration (e.g., capture for 60 seconds)\n";
    std::cout << "  3) Unlimited (manual stop with Ctrl+C)\n\n";
    
    int choice = get_choice(1, 3);
    std::string input;
    
    switch (choice) {
        case 1:
            std::cout << "\nEnter packet count: ";
            std::getline(std::cin, input);
            opts.packet_count = std::atoi(input.c_str());
            opts.capture_duration = 0;
            std::cout << "[+] Will capture " << opts.packet_count << " packets\n";
            break;
        case 2:
            std::cout << "\nEnter duration in seconds: ";
            std::getline(std::cin, input);
            opts.capture_duration = std::atoi(input.c_str());
            opts.packet_count = 0;
            std::cout << "[+] Will capture for " << opts.capture_duration << " seconds\n";
            break;
        case 3:
            opts.packet_count = 0;
            opts.capture_duration = 0;
            std::cout << "[+] Unlimited capture (stop with Ctrl+C)\n";
            break;
    }
    
    std::cout << "\nPress Enter to continue...";
    std::getline(std::cin, input);
}

static void setup_ethertype_filter(CliOptions& opts) {
    clear_screen();
    print_header("Step 3: EtherType Filter");
    
    struct EtherTypeOption {
        std::string name;
        std::string filter;
        uint16_t ethertype;
    };
    
    std::vector<EtherTypeOption> ethertypes = {
        {"IPv4",        "ip",           0x0800},
        {"IPv6",        "ip6",          0x86DD},
        {"ARP",         "arp",          0x0806},
        {"RARP",        "rarp",         0x8035},
        {"VLAN",        "vlan",         0x8100},
        {"PPPoE Disc",  "pppoed",       0x8863},
        {"PPPoE Sess",  "pppoes",       0x8864},
        {"LLDP",        "ether proto 0x88cc", 0x88CC},
        {"MPLS",        "mpls",         0x8847}
    };
    
    std::cout << "Select EtherType filter(s):\n\n";
    for (size_t i = 0; i < ethertypes.size(); ++i) {
        std::cout << "  " << (i + 1) << ") " << ethertypes[i].name 
                  << " (0x" << std::hex << ethertypes[i].ethertype << std::dec << ")\n";
    }
    std::cout << "  0) No filter / Custom BPF\n\n";
    
    std::cout << "Enter choices separated by spaces (e.g., '1 2 3') or single choice: ";
    std::string input;
    std::getline(std::cin, input);
    
    if (input.empty() || input == "0") {
        std::cout << "\nEnter custom BPF filter (or leave empty): ";
        std::getline(std::cin, opts.bpf_filter);
        if (!opts.bpf_filter.empty()) {
            std::cout << "[+] Custom filter: " << opts.bpf_filter << "\n";
        } else {
            std::cout << "[+] No filter applied\n";
        }
    } else {
        std::istringstream iss(input);
        std::vector<int> choices;
        int choice;
        
        while (iss >> choice) {
            if (choice > 0 && choice <= (int)ethertypes.size()) {
                choices.push_back(choice - 1);
            }
        }
        
        if (choices.empty()) {
            std::cout << "[!] No valid choices. No filter applied.\n";
        } else {
            std::ostringstream filter;
            for (size_t i = 0; i < choices.size(); ++i) {
                if (i > 0) filter << " or ";
                filter << ethertypes[choices[i]].filter;
            }
            opts.bpf_filter = filter.str();
            
            std::cout << "\n[+] Filter applied: " << opts.bpf_filter << "\n";
            std::cout << "[+] Selected types: ";
            for (size_t i = 0; i < choices.size(); ++i) {
                if (i > 0) std::cout << ", ";
                std::cout << ethertypes[choices[i]].name;
            }
            std::cout << "\n";
        }
    }
    
    std::cout << "\nPress Enter to continue...";
    std::getline(std::cin, input);
}

static void setup_protocol_filter(CliOptions& opts) {
    clear_screen();
    print_header("Step 4: Protocol Filter (Optional)");
    
    std::cout << "Add protocol-specific filter?\n\n";
    std::cout << "  1) TCP (specific port)\n";
    std::cout << "  2) UDP (specific port)\n";
    std::cout << "  3) ICMP\n";
    std::cout << "  4) DNS (port 53)\n";
    std::cout << "  5) HTTP/HTTPS (ports 80, 443)\n";
    std::cout << "  6) SSH (port 22)\n";
    std::cout << "  7) Custom filter\n";
    std::cout << "  0) Skip\n\n";
    
    int choice = get_choice(0, 7);
    std::string input;
    std::string additional_filter;
    
    switch (choice) {
        case 1: {
            while (true) {
                std::cout << "\nEnter TCP port (1-65535): ";
                std::getline(std::cin, input);
                int port = std::atoi(input.c_str());
                if (port > 0 && port <= 65535) {
                    additional_filter = "tcp port " + input;
                    break;
                }
                std::cout << "[!] Invalid port number\n";
            }
            break;
        }
        case 2: {
            while (true) {
                std::cout << "\nEnter UDP port (1-65535): ";
                std::getline(std::cin, input);
                int port = std::atoi(input.c_str());
                if (port > 0 && port <= 65535) {
                    additional_filter = "udp port " + input;
                    break;
                }
                std::cout << "[!] Invalid port number\n";
            }
            break;
        }
        case 3:
            additional_filter = "icmp";
            break;
        case 4:
            additional_filter = "port 53";
            break;
        case 5:
            additional_filter = "tcp port 80 or tcp port 443";
            break;
        case 6:
            additional_filter = "tcp port 22";
            break;
        case 7: {
            while (true) {
                std::cout << "\nEnter custom BPF filter: ";
                std::getline(std::cin, additional_filter);
                
                if (additional_filter.empty()) {
                    std::cout << "[!] Filter cannot be empty. Use option 0 to skip.\n";
                    continue;
                }
                
                if (validate_bpf_filter(additional_filter)) {
                    std::cout << "[+] Filter syntax looks valid\n";
                    break;
                } else {
                    std::cout << "[!] Invalid filter syntax. Try again or press Ctrl+C to cancel.\n";
                    std::cout << "\nExamples:\n";
                    std::cout << "  tcp port 8080\n";
                    std::cout << "  udp and dst port 53\n";
                    std::cout << "  host 192.168.1.1 and port 22\n";
                    std::cout << "  (tcp port 80) or (tcp port 443)\n\n";
                }
            }
            break;
        }
        case 0:
            std::cout << "[+] No protocol filter\n";
            break;
    }
    
    if (!additional_filter.empty()) {
        if (!opts.bpf_filter.empty()) {
            opts.bpf_filter = "(" + opts.bpf_filter + ") and (" + additional_filter + ")";
        } else {
            opts.bpf_filter = additional_filter;
        }
        std::cout << "[+] Protocol filter added: " << additional_filter << "\n";
    }
    
    std::cout << "\nPress Enter to continue...";
    std::getline(std::cin, input);
}

static void setup_output(CliOptions& opts) {
    clear_screen();
    print_header("Step 5: Output Options");
    
    std::cout << "Output configuration:\n\n";
    std::cout << "  1) Console only\n";
    std::cout << "  2) Save to file (PCAP format)\n";
    std::cout << "  3) Both console and file\n\n";
    
    int choice = get_choice(1, 3);
    std::string input;
    
    if (choice == 2 || choice == 3) {
        std::cout << "\nEnter output filename: ";
        std::getline(std::cin, opts.output_file);
        std::cout << "[+] Will save to: " << opts.output_file << "\n";
    }
    
    std::cout << "\nVerbose output? (y/n): ";
    std::getline(std::cin, input);
    opts.verbose = (input == "y" || input == "Y");
    
    std::cout << "\nPress Enter to continue...";
    std::getline(std::cin, input);
}

static void print_final_config(const CliOptions& opts) {
    clear_screen();
    print_header("Configuration Summary");
    
    std::cout << "  Interface:       " << opts.interface << "\n";
    std::cout << "  Promiscuous:     " << (opts.promiscuous ? "YES" : "NO") << "\n";
    std::cout << "  Capture limit:   ";
    if (opts.packet_count > 0) {
        std::cout << opts.packet_count << " packets\n";
    } else if (opts.capture_duration > 0) {
        std::cout << opts.capture_duration << " seconds\n";
    } else {
        std::cout << "Unlimited\n";
    }
    std::cout << "  BPF filter:      " << (opts.bpf_filter.empty() ? "(none)" : opts.bpf_filter) << "\n";
    std::cout << "  Output file:     " << (opts.output_file.empty() ? "(console only)" : opts.output_file) << "\n";
    std::cout << "  Verbose:         " << (opts.verbose ? "YES" : "NO") << "\n";
    
    std::cout << "\n╔═══════════════════════════════════════════╗\n";
    std::cout << "║  Ready to start capture                  ║\n";
    std::cout << "╚═══════════════════════════════════════════╝\n\n";
    
    std::cout << "Press Enter to start or Ctrl+C to cancel...";
    std::string input;
    std::getline(std::cin, input);
}


static void interactive_setup(CliOptions& opts) {
    setup_interface(opts);
    setup_capture_limit(opts);
    setup_ethertype_filter(opts);
    setup_protocol_filter(opts);
    setup_output(opts);
    print_final_config(opts);
}

void print_usage(const char* prog_name) {
    std::cout << "Usage: " << prog_name << " [OPTIONS]\n";
    std::cout << "\nOptions:\n";
    std::cout << "  -I, --interface <name>    Network interface to capture\n";
    std::cout << "  -p, --promiscuous         Enable promiscuous mode\n";
    std::cout << "  -f, --filter <bpf>        Apply BPF filter expression\n";
    std::cout << "  -o, --output <file>       Write packets to file\n";
    std::cout << "  -c, --count <num>         Capture only <num> packets\n";
    std::cout << "  -t, --time <sec>          Capture for <sec> seconds\n";
    std::cout << "  -v, --verbose             Verbose output\n";
    std::cout << "  -i, --interactive         Interactive configuration mode\n";
    std::cout << "  -h, --help                Show this help\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << prog_name << "                              # Interactive mode\n";
    std::cout << "  " << prog_name << " -I eth0 -p -f \"tcp port 80\"  # Direct mode\n";
    std::cout << "  " << prog_name << " -i                            # Force interactive\n";
}

bool parse_cli(int argc, char** argv, CliOptions& opts) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return false;
        }
        else if (arg == "-i" || arg == "--interactive") {
            opts.interactive = true;
        }
        else if (arg == "-I" || arg == "--interface") {
            if (i + 1 < argc) {
                opts.interface = argv[++i];
            } else {
                std::cerr << "[!] Error: " << arg << " requires an argument\n";
                return false;
            }
        }
        else if (arg == "-p" || arg == "--promiscuous") {
            opts.promiscuous = true;
        }
        else if (arg == "-f" || arg == "--filter") {
            if (i + 1 < argc) {
                opts.bpf_filter = argv[++i];
            } else {
                std::cerr << "[!] Error: " << arg << " requires an argument\n";
                return false;
            }
        }
        else if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) {
                opts.output_file = argv[++i];
            } else {
                std::cerr << "[!] Error: " << arg << " requires an argument\n";
                return false;
            }
        }
        else if (arg == "-c" || arg == "--count") {
            if (i + 1 < argc) {
                opts.packet_count = std::atoi(argv[++i]);
            } else {
                std::cerr << "[!] Error: " << arg << " requires an argument\n";
                return false;
            }
        }
        else if (arg == "-t" || arg == "--time") {
            if (i + 1 < argc) {
                opts.capture_duration = std::atoi(argv[++i]);
            } else {
                std::cerr << "[!] Error: " << arg << " requires an argument\n";
                return false;
            }
        }
        else if (arg == "-v" || arg == "--verbose") {
            opts.verbose = true;
        }
        else {
            std::cerr << "[!] Error: unknown option " << arg << "\n";
            return false;
        }
    }
    
    return true;
}

bool handle_cli(int argc, char** argv, CliOptions& opts) {
    if (!parse_cli(argc, argv, opts)) {
        return false;
    }
    
    if (argc == 1 || opts.interactive) {
        interactive_setup(opts);
    }
    
    return true;
}
