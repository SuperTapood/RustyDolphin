#include "Core/FilterParser.h"
#include "Core/PacketDecoder.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>

namespace {
int failures = 0;
void check(bool condition, std::string_view name) {
	if (!condition) {
		std::cerr << "FAIL: " << name << '\n';
		++failures;
	}
}
}

int main() {
	check(!core::decodeEthernet(std::array<std::uint8_t, 13>{}), "truncated Ethernet is rejected");

	std::array<std::uint8_t, 34> ipv4{};
	ipv4[14] = 0x45;
	ipv4[16] = 0;
	ipv4[17] = 20;
	ipv4[23] = 6;
	auto v4 = core::decodeIPv4(ipv4);
	check(v4 && v4->version == 4 && v4->headerLength == 20 && v4->protocol == 6, "IPv4 IHL is decoded");
	ipv4[14] = 0x44;
	check(!core::decodeIPv4(ipv4), "short IPv4 IHL is rejected");

	std::array<std::uint8_t, 54> ipv6{};
	ipv6[14] = 0x6a;
	ipv6[15] = 0xb1;
	ipv6[16] = 0x23;
	ipv6[17] = 0x45;
	ipv6[20] = 17;
	auto v6 = core::decodeIPv6(ipv6);
	check(v6 && v6->trafficClass == 0xab && v6->flowLabel == 0x12345 && v6->nextHeader == 17, "IPv6 fields are decoded");

	std::array<std::uint8_t, 20> tcp{};
	tcp[12] = 0x51;
	tcp[13] = 0x12;
	auto tcpHeader = core::decodeTcp(tcp, 0);
	check(tcpHeader && tcpHeader->headerLength == 20 && tcpHeader->flags == 0x112, "TCP length and NS flag are decoded");
	tcp[12] = 0x40;
	check(!core::decodeTcp(tcp, 0), "short TCP header is rejected");

	std::array<std::uint8_t, 8> udp{};
	udp[4] = 0;
	udp[5] = 7;
	check(!core::decodeUdp(udp, 0), "short UDP length is rejected");
	udp[5] = 8;
	check(core::decodeUdp(udp, 0).has_value(), "minimum UDP length is accepted");

	auto filter = core::parseFilter(" Proto = TCP, dport = 443 ");
	check(filter && filter->at("proto") == "tcp" && filter->at("dport") == "443", "filter grammar trims and normalizes");
	check(!core::parseFilter("proto"), "filter without equals is rejected");
	check(!core::parseFilter("wat=x"), "unknown filter key is rejected");
	check(!core::parseFilter("proto="), "empty filter value is rejected");

	if (failures == 0) std::cout << "All core tests passed.\n";
	return failures == 0 ? 0 : 1;
}
