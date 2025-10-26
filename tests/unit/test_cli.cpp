#include <gtest/gtest.h>

#include <iostream>
#include <sstream>

#include "cli.hpp"

class CliTest : public ::testing::Test {
protected:
    CliOptions opts;
};

TEST_F(CliTest, DefaultCliOptions) {
    EXPECT_EQ(opts.interface, "eth0");
    EXPECT_FALSE(opts.promiscuous);
    EXPECT_EQ(opts.output_file, "");
    EXPECT_EQ(opts.packet_count, 0);
    EXPECT_EQ(opts.capture_duration, 0);
    EXPECT_FALSE(opts.verbose);
    EXPECT_FALSE(opts.interactive);
    EXPECT_TRUE(opts.show_parsed);
    EXPECT_FALSE(opts.show_hex);
}

TEST_F(CliTest, ParseInterfaceShort) {
    const char* argv[] = {"prog", "-I", "wlan0"};
    ASSERT_TRUE(parse_cli(3, (char**) argv, opts));
    EXPECT_EQ(opts.interface, "wlan0");
}

TEST_F(CliTest, ParseInterfaceLong) {
    const char* argv[] = {"prog", "--interface", "eth1"};
    ASSERT_TRUE(parse_cli(3, (char**) argv, opts));
    EXPECT_EQ(opts.interface, "eth1");
}

TEST_F(CliTest, ParsePromiscuousShort) {
    const char* argv[] = {"prog", "-p"};
    ASSERT_TRUE(parse_cli(2, (char**) argv, opts));
    EXPECT_TRUE(opts.promiscuous);
}

TEST_F(CliTest, ParsePromiscuousLong) {
    const char* argv[] = {"prog", "--promiscuous"};
    ASSERT_TRUE(parse_cli(2, (char**) argv, opts));
    EXPECT_TRUE(opts.promiscuous);
}

TEST_F(CliTest, ParseOutputShort) {
    const char* argv[] = {"prog", "-o", "capture.pcap"};
    ASSERT_TRUE(parse_cli(3, (char**) argv, opts));
    EXPECT_EQ(opts.output_file, "capture.pcap");
}

TEST_F(CliTest, ParseOutputLong) {
    const char* argv[] = {"prog", "--output", "traffic.pcap"};
    ASSERT_TRUE(parse_cli(3, (char**) argv, opts));
    EXPECT_EQ(opts.output_file, "traffic.pcap");
}

TEST_F(CliTest, ParseCountShort) {
    const char* argv[] = {"prog", "-c", "100"};
    ASSERT_TRUE(parse_cli(3, (char**) argv, opts));
    EXPECT_EQ(opts.packet_count, 100);
}

TEST_F(CliTest, ParseCountLong) {
    const char* argv[] = {"prog", "--count", "500"};
    ASSERT_TRUE(parse_cli(3, (char**) argv, opts));
    EXPECT_EQ(opts.packet_count, 500);
}

TEST_F(CliTest, ParseTimeShort) {
    const char* argv[] = {"prog", "-t", "60"};
    ASSERT_TRUE(parse_cli(3, (char**) argv, opts));
    EXPECT_EQ(opts.capture_duration, 60);
}

TEST_F(CliTest, ParseTimeLong) {
    const char* argv[] = {"prog", "--time", "120"};
    ASSERT_TRUE(parse_cli(3, (char**) argv, opts));
    EXPECT_EQ(opts.capture_duration, 120);
}

TEST_F(CliTest, ParseVerboseShort) {
    const char* argv[] = {"prog", "-v"};
    ASSERT_TRUE(parse_cli(2, (char**) argv, opts));
    EXPECT_TRUE(opts.verbose);
}

TEST_F(CliTest, ParseVerboseLong) {
    const char* argv[] = {"prog", "--verbose"};
    ASSERT_TRUE(parse_cli(2, (char**) argv, opts));
    EXPECT_TRUE(opts.verbose);
}

TEST_F(CliTest, ParseHexShort) {
    const char* argv[] = {"prog", "-x"};
    ASSERT_TRUE(parse_cli(2, (char**) argv, opts));
    EXPECT_TRUE(opts.show_hex);
    EXPECT_FALSE(opts.show_parsed);
}

TEST_F(CliTest, ParseHexLong) {
    const char* argv[] = {"prog", "--hex"};
    ASSERT_TRUE(parse_cli(2, (char**) argv, opts));
    EXPECT_TRUE(opts.show_hex);
}

TEST_F(CliTest, ParseParsedShort) {
    const char* argv[] = {"prog", "-P"};
    ASSERT_TRUE(parse_cli(2, (char**) argv, opts));
    EXPECT_TRUE(opts.show_parsed);
}

TEST_F(CliTest, ParseParsedLong) {
    const char* argv[] = {"prog", "--parsed"};
    ASSERT_TRUE(parse_cli(2, (char**) argv, opts));
    EXPECT_TRUE(opts.show_parsed);
}

TEST_F(CliTest, ParseBothParsedAndHex) {
    const char* argv[] = {"prog", "-P", "-x"};
    ASSERT_TRUE(parse_cli(3, (char**) argv, opts));
    EXPECT_TRUE(opts.show_parsed);
    EXPECT_TRUE(opts.show_hex);
}

TEST_F(CliTest, ParseInteractiveShort) {
    const char* argv[] = {"prog", "-i"};
    ASSERT_TRUE(parse_cli(2, (char**) argv, opts));
    EXPECT_TRUE(opts.interactive);
}

TEST_F(CliTest, ParseInteractiveLong) {
    const char* argv[] = {"prog", "--interactive"};
    ASSERT_TRUE(parse_cli(2, (char**) argv, opts));
    EXPECT_TRUE(opts.interactive);
}

TEST_F(CliTest, CombinedOptions) {
    const char* argv[] = {"prog", "-I", "eth0", "-p", "-c", "1000", "-v", "-x", "-o", "out.pcap"};
    ASSERT_TRUE(parse_cli(10, (char**) argv, opts));
    EXPECT_EQ(opts.interface, "eth0");
    EXPECT_TRUE(opts.promiscuous);
    EXPECT_EQ(opts.packet_count, 1000);
    EXPECT_TRUE(opts.verbose);
    EXPECT_TRUE(opts.show_hex);
    EXPECT_EQ(opts.output_file, "out.pcap");
}

TEST_F(CliTest, HelpOptionReturnsTrue) {
    const char* argv[] = {"prog", "-h"};
    EXPECT_FALSE(parse_cli(2, (char**) argv, opts));
}

TEST_F(CliTest, HelpLongOptionReturnsTrue) {
    const char* argv[] = {"prog", "--help"};
    EXPECT_FALSE(parse_cli(2, (char**) argv, opts));
}

TEST_F(CliTest, UnknownOptionReturnsFalse) {
    const char* argv[] = {"prog", "-z"};
    EXPECT_FALSE(parse_cli(2, (char**) argv, opts));
}

TEST_F(CliTest, MissingInterfaceArgumentReturnsFalse) {
    const char* argv[] = {"prog", "-I"};
    EXPECT_FALSE(parse_cli(2, (char**) argv, opts));
}

TEST_F(CliTest, MissingOutputArgumentReturnsFalse) {
    const char* argv[] = {"prog", "-o"};
    EXPECT_FALSE(parse_cli(2, (char**) argv, opts));
}

TEST_F(CliTest, MissingCountArgumentReturnsFalse) {
    const char* argv[] = {"prog", "-c"};
    EXPECT_FALSE(parse_cli(2, (char**) argv, opts));
}

TEST_F(CliTest, MissingTimeArgumentReturnsFalse) {
    const char* argv[] = {"prog", "-t"};
    EXPECT_FALSE(parse_cli(2, (char**) argv, opts));
}

TEST_F(CliTest, CountZero) {
    const char* argv[] = {"prog", "-c", "0"};
    ASSERT_TRUE(parse_cli(3, (char**) argv, opts));
    EXPECT_EQ(opts.packet_count, 0);
}

TEST_F(CliTest, CountLarge) {
    const char* argv[] = {"prog", "-c", "1000000"};
    ASSERT_TRUE(parse_cli(3, (char**) argv, opts));
    EXPECT_EQ(opts.packet_count, 1000000);
}

TEST_F(CliTest, TimeZero) {
    const char* argv[] = {"prog", "-t", "0"};
    ASSERT_TRUE(parse_cli(3, (char**) argv, opts));
    EXPECT_EQ(opts.capture_duration, 0);
}

TEST_F(CliTest, TimeLarge) {
    const char* argv[] = {"prog", "-t", "86400"};  // 24 hours
    ASSERT_TRUE(parse_cli(3, (char**) argv, opts));
    EXPECT_EQ(opts.capture_duration, 86400);
}

TEST_F(CliTest, InterfaceWithSpecialChars) {
    const char* argv[] = {"prog", "-I", "eth0:1"};
    ASSERT_TRUE(parse_cli(3, (char**) argv, opts));
    EXPECT_EQ(opts.interface, "eth0:1");
}

TEST_F(CliTest, OutputFileWithPath) {
    const char* argv[] = {"prog", "-o", "/tmp/capture.pcap"};
    ASSERT_TRUE(parse_cli(3, (char**) argv, opts));
    EXPECT_EQ(opts.output_file, "/tmp/capture.pcap");
}

TEST_F(CliTest, OutputFileRelativePath) {
    const char* argv[] = {"prog", "-o", "./captures/traffic.pcap"};
    ASSERT_TRUE(parse_cli(3, (char**) argv, opts));
    EXPECT_EQ(opts.output_file, "./captures/traffic.pcap");
}

TEST_F(CliTest, NegativeCountBecomesZero) {
    const char* argv[] = {"prog", "-c", "-100"};
    ASSERT_TRUE(parse_cli(3, (char**) argv, opts));
    EXPECT_LT(opts.packet_count, 0);  // atoi gives negative
}

TEST_F(CliTest, NonNumericCountBecomesZero) {
    const char* argv[] = {"prog", "-c", "abc"};
    ASSERT_TRUE(parse_cli(3, (char**) argv, opts));
    EXPECT_EQ(opts.packet_count, 0);
}

TEST_F(CliTest, NonNumericTimeBecomesZero) {
    const char* argv[] = {"prog", "-t", "xyz"};
    ASSERT_TRUE(parse_cli(3, (char**) argv, opts));
    EXPECT_EQ(opts.capture_duration, 0);
}

TEST_F(CliTest, DefaultToParsedIfNeitherHexNorParsed) {
    const char* argv[] = {"prog"};
    ASSERT_TRUE(parse_cli(1, (char**) argv, opts));
    EXPECT_TRUE(opts.show_parsed);
    EXPECT_FALSE(opts.show_hex);
}

TEST_F(CliTest, MultipleInterfaces) {
    const char* argv[] = {"prog", "-I", "eth0", "-I", "eth1"};
    ASSERT_TRUE(parse_cli(5, (char**) argv, opts));
    EXPECT_EQ(opts.interface, "eth1");  // Last one wins
}

TEST_F(CliTest, MultipleOutputFiles) {
    const char* argv[] = {"prog", "-o", "file1.pcap", "-o", "file2.pcap"};
    ASSERT_TRUE(parse_cli(5, (char**) argv, opts));
    EXPECT_EQ(opts.output_file, "file2.pcap");  // Last one wins
}

TEST_F(CliTest, EmptyInterface) {
    const char* argv[] = {"prog", "-I", ""};
    ASSERT_TRUE(parse_cli(3, (char**) argv, opts));
    EXPECT_EQ(opts.interface, "");
}

TEST_F(CliTest, LongInterfaceName) {
    std::string long_name = "veryverylonginterfacename";
    const char* argv[] = {"prog", "-I", long_name.c_str()};
    ASSERT_TRUE(parse_cli(3, (char**) argv, opts));
    EXPECT_EQ(opts.interface, long_name);
}

TEST_F(CliTest, AllOptionsToggled) {
    const char* argv[] = {"prog", "-I", "lo", "-p", "-c", "42",        "-t",
                          "99",   "-v", "-x", "-P", "-o", "test.pcap", "-i"};
    ASSERT_TRUE(parse_cli(sizeof(argv) / sizeof(argv[0]), (char**) argv, opts));
    EXPECT_EQ(opts.interface, "lo");
    EXPECT_TRUE(opts.promiscuous);
    EXPECT_EQ(opts.packet_count, 42);
    EXPECT_EQ(opts.capture_duration, 99);
    EXPECT_TRUE(opts.verbose);
    EXPECT_TRUE(opts.show_hex);
    EXPECT_TRUE(opts.show_parsed);
    EXPECT_EQ(opts.output_file, "test.pcap");
    EXPECT_TRUE(opts.interactive);
}

TEST_F(CliTest, MixedShortLongOptions) {
    const char* argv[] = {"prog", "-I", "eth0", "--promiscuous", "-c", "100", "--verbose"};
    ASSERT_TRUE(parse_cli(7, (char**) argv, opts));
    EXPECT_EQ(opts.interface, "eth0");
    EXPECT_TRUE(opts.promiscuous);
    EXPECT_EQ(opts.packet_count, 100);
    EXPECT_TRUE(opts.verbose);
}

TEST_F(CliTest, OnlyProgramNameReturnsFalse) {
    const char* argv[] = {"prog"};
    ASSERT_TRUE(parse_cli(1, (char**) argv, opts));
    EXPECT_FALSE(opts.interactive);
}

TEST_F(CliTest, PromiscuousWithoutValue) {
    const char* argv[] = {"prog", "-p", "-I", "eth0"};
    ASSERT_TRUE(parse_cli(4, (char**) argv, opts));
    EXPECT_TRUE(opts.promiscuous);
    EXPECT_EQ(opts.interface, "eth0");
}

TEST_F(CliTest, HexEnablesShowHexOnly) {
    const char* argv[] = {"prog", "-x"};
    ASSERT_TRUE(parse_cli(2, (char**) argv, opts));
    EXPECT_TRUE(opts.show_hex);
    EXPECT_FALSE(opts.show_parsed);
}

TEST_F(CliTest, CountAndTimeExclusive) {
    const char* argv[] = {"prog", "-c", "50", "-t", "30"};
    ASSERT_TRUE(parse_cli(5, (char**) argv, opts));
    EXPECT_EQ(opts.packet_count, 50);
    EXPECT_EQ(opts.capture_duration, 30);
}
