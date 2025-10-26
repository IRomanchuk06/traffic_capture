#include "cli.hpp"

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

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

static void clear_screen() {
    std::cout << "\033[2J\033[H";
}

static int get_choice(int min, int max) {
    std::string input;
    while (true) {
        std::cout << "Choice: ";
        std::getline(std::cin, input);

        if (input.empty())
            continue;

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
    for (size_t i = title.length(); i < 41; ++i)
        std::cout << " ";
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

    int choice = get_choice(0, static_cast<int>(interfaces.size()));

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
        default:
            break;
    }

    std::cout << "\nPress Enter to continue...";
    std::getline(std::cin, input);
}

static void setup_display_mode(CliOptions& opts) {
    clear_screen();
    print_header("Step 3: Display Mode");

    std::cout << "Choose packet display mode:\n\n";
    std::cout << "  1) Parsed output (protocol details)\n";
    std::cout << "  2) HEX dump only\n";
    std::cout << "  3) Both (parsed + HEX, like Wireshark)\n\n";

    int choice = get_choice(1, 3);

    switch (choice) {
        case 1:
            opts.show_parsed = true;
            opts.show_hex = false;
            std::cout << "\n[+] Will show parsed protocol details\n";
            break;
        case 2:
            opts.show_parsed = false;
            opts.show_hex = true;
            std::cout << "\n[+] Will show HEX dump only\n";
            break;
        case 3:
            opts.show_parsed = true;
            opts.show_hex = true;
            std::cout << "\n[+] Will show both parsed details and HEX dump\n";
            break;
        default:
            break;
    }

    std::cout << "\nPress Enter to continue...";
    std::string input;
    std::getline(std::cin, input);
}

static void setup_output(CliOptions& opts) {
    clear_screen();
    print_header("Step 4: Output Options");

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

    std::cout << "  Display mode:    ";
    if (opts.show_parsed && opts.show_hex) {
        std::cout << "Parsed + HEX\n";
    } else if (opts.show_parsed) {
        std::cout << "Parsed only\n";
    } else {
        std::cout << "HEX only\n";
    }

    std::cout << "  Output file:     "
              << (opts.output_file.empty() ? "(console only)" : opts.output_file) << "\n";
    std::cout << "  Verbose:         " << (opts.verbose ? "YES" : "NO") << "\n";

    std::cout << "\n╔═══════════════════════════════════════════╗\n";
    std::cout << "║  Ready to start capture                   ║\n";
    std::cout << "╚═══════════════════════════════════════════╝\n\n";

    std::cout << "Press Enter to start or Ctrl+C to cancel...";
    std::string input;
    std::getline(std::cin, input);
}

static void interactive_setup(CliOptions& opts) {
    setup_interface(opts);
    setup_capture_limit(opts);
    setup_display_mode(opts);
    setup_output(opts);
    print_final_config(opts);
}

void print_usage(const char* prog_name) {
    std::cout << "Usage: " << prog_name << " [OPTIONS]\n";
    std::cout << "\nOptions:\n";
    std::cout << "  -I, --interface <name>    Network interface to capture\n";
    std::cout << "  -p, --promiscuous         Enable promiscuous mode\n";
    std::cout << "  -o, --output <file>       Write packets to file\n";
    std::cout << "  -c, --count <num>         Capture only <num> packets\n";
    std::cout << "  -t, --time <sec>          Capture for <sec> seconds\n";
    std::cout << "  -v, --verbose             Verbose output\n";
    std::cout << "  -x, --hex                 Show HEX dump\n";
    std::cout << "  -P, --parsed              Show parsed protocol details\n";
    std::cout << "  -i, --interactive         Interactive configuration mode\n";
    std::cout << "  -h, --help                Show this help\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << prog_name << "                    # Interactive mode\n";
    std::cout << "  " << prog_name << " -I eth0 -p -c 100  # Direct mode\n";
    std::cout << "  " << prog_name << " -P -x              # Both parsed and HEX\n";
}

bool parse_cli(int argc, char** argv, CliOptions& opts) {
    bool explicit_hex = false;
    bool explicit_parsed = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return false;
        } else if (arg == "-i" || arg == "--interactive") {
            opts.interactive = true;
        } else if (arg == "-I" || arg == "--interface") {
            if (i + 1 < argc) {
                opts.interface = argv[++i];
            } else {
                std::cerr << "[!] Error: " << arg << " requires an argument\n";
                return false;
            }
        } else if (arg == "-p" || arg == "--promiscuous") {
            opts.promiscuous = true;
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) {
                opts.output_file = argv[++i];
            } else {
                std::cerr << "[!] Error: " << arg << " requires an argument\n";
                return false;
            }
        } else if (arg == "-c" || arg == "--count") {
            if (i + 1 < argc) {
                opts.packet_count = std::atoi(argv[++i]);
            } else {
                std::cerr << "[!] Error: " << arg << " requires an argument\n";
                return false;
            }
        } else if (arg == "-t" || arg == "--time") {
            if (i + 1 < argc) {
                opts.capture_duration = std::atoi(argv[++i]);
            } else {
                std::cerr << "[!] Error: " << arg << " requires an argument\n";
                return false;
            }
        } else if (arg == "-v" || arg == "--verbose") {
            opts.verbose = true;
        } else if (arg == "-x" || arg == "--hex") {
            opts.show_hex = true;
            explicit_hex = true;
        } else if (arg == "-P" || arg == "--parsed") {
            opts.show_parsed = true;
            explicit_parsed = true;
        } else {
            std::cerr << "[!] Error: unknown option " << arg << "\n";
            return false;
        }
    }

    if (!explicit_hex && !explicit_parsed) {
        opts.show_parsed = true;
        opts.show_hex = false;
    } else if (explicit_hex && !explicit_parsed) {
        opts.show_parsed = false;
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
