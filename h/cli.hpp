#ifndef CLI_HPP
#define CLI_HPP

#include <string>

struct CliOptions {
    std::string interface = "eth0";
    bool promiscuous = false;
    std::string bpf_filter;
    std::string output_file;
    int packet_count = 0;
    int capture_duration = 0;
    bool verbose = false;
    bool interactive = false;
};

bool handle_cli(int argc, char** argv, CliOptions& opts);

void print_usage(const char* prog_name);
bool parse_cli(int argc, char** argv, CliOptions& opts);

#endif // CLI_HPP
