#include "IPV4.h"

#include <sstream>
#include <vector>
#include "../../../../Base/Logger.h"
#include "../../../Capture.h"
#include <iostream>
#include <bitset>
#include <stdexcept>
#include <cstdio>

namespace {
bool isPublicIPv4(const std::string& address) {
	unsigned int a, b, c, d;
	char trailing;
	if (sscanf_s(address.c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &trailing, 1) != 4 ||
		a > 255 || b > 255 || c > 255 || d > 255) {
		return false;
	}

	if (a == 0 || a == 10 || a == 127 || a >= 224) return false;
	if (a == 100 && b >= 64 && b <= 127) return false;       // carrier-grade NAT
	if (a == 169 && b == 254) return false;                  // link-local
	if (a == 172 && b >= 16 && b <= 31) return false;
	if (a == 192 && b == 168) return false;
	if (a == 198 && (b == 18 || b == 19)) return false;      // benchmark network
	return true;
}
}
#include <ws2def.h>
#include "../../../../Base/ProtocolCatalog.h"
#include "../../../../Win/SDK.h"

IPV4::IPV4(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx) : Packet(header, pkt_data, idx) {
	auto start = getPos();
	const auto versionAndLength = static_cast<unsigned char>(parseChar());
	m_version = versionAndLength >> 4;
	m_headerLength = (versionAndLength & 0x0F) * 4;
	if (m_version != 4 || m_headerLength < 20) {
		throw std::invalid_argument("invalid IPv4 header");
	}
	m_differServ = parseChar();

	m_totalLength = parseShort();

	m_identification = parseShort();

	m_flags = (pkt_data[getPos()] & 224);

	m_fragmentationOffset = parseShort() & 8191;

	m_ttl = parseChar();

	m_proto = parseChar();

	m_headerChecksum = parseShort();

	m_srcAddr = parseIPV4();

	m_destAddr = parseIPV4();

	int diff = (m_headerLength + start) - getPos();

	m_IPoptionsCount = 0;

	while (diff > 0) {
		m_IPoptionsCount++;
		auto temp = getPos();

		int code = pkt_data[getPos()] & 31;

		constexpr auto routerAlert = 20;

		switch (code) {
		case routerAlert:
			m_opts.push_back(std::make_unique<RouterAlert>(this));
			m_optSize += m_opts.at(m_opts.size() - 1)->m_length;
			break;
		default:
#ifdef _DEBUG
			std::stringstream ss;
			ss << "bad ip option of packet data: " << code;
			Logger::log(ss.str());
#endif
			// Unsupported options are still part of this header. Consume the
			// remainder so Release builds cannot spin without advancing.
			parse(diff);
			diff = 0;
			break;
		}

		diff -= (getPos() - temp);
		m_expands.insert({ std::format("option %d", m_IPoptionsCount - 1), false });
	}

	Packet::m_strType = "IPV4";

	m_expands.insert({ "IPV4 Title", false });
	m_expands.insert({ "DifferServ", false });
	m_expands.insert({ "Flags", false });
	m_expands.insert({ "Options General", false });

	m_properties.insert({ "ip", "v4" });
	m_properties.insert({ "saddr", m_srcAddr });
	m_properties.insert({ "daddr", m_destAddr });
}

std::string IPV4::toString() {
	std::stringstream ss;

	ss << "IPV4 Packet at " << m_texts["time"] << " of length " << m_totalLength << " from " << m_srcAddr << " to " << m_destAddr << " transfer protocol is " << m_proto << " with options: ";

	for (size_t i = 0; i < m_IPoptionsCount; i++) {
		ss << m_opts.at(i)->toString() << ", ";
	}

	ss << "\n";

	return ss.str();
}

json IPV4::jsonify() {
	auto j = Packet::jsonify();

	j["IPV4"] = "start";
	j["IPV4 Header Length"] = m_headerLength;
	j["Differentiated Services"] = m_differServ;
	j["Total Length"] = m_totalLength;
	j["Identification"] = m_identification;
	j["Flags"] = m_flags;
	j["Fragmentation Offset"] = m_fragmentationOffset;
	j["Time to Live"] = m_ttl;
	j["protocol"] = m_proto;
	j["IPV4 Checksum"] = m_headerChecksum;
	j["Source Address"] = m_srcAddr;
	j["Destination Address"] = m_destAddr;
	j["IP Options Count"] = m_IPoptionsCount;

	if (m_IPoptionsCount > 0) {
		std::stringstream ss;
		for (size_t i = 0; i < m_IPoptionsCount; i++) {
			ss << m_opts.at(i)->toString() << ", ";
		}
		j["IP Options"] = ss.str();
	}

	return j;
}

std::map<std::string, std::string> IPV4::getTexts() {
	if (m_texts.empty()) {
		Packet::getTexts();

		m_texts["IPTitle"] = std::format("Internet Protocol Version 4, Src: {}, Dst: {}", m_srcAddr, m_destAddr);

		m_texts["headerLen"] = std::format("\t. . . . {} = Header Length: {} bytes ({})", std::bitset<4>(m_headerLength).to_string(), (int)m_headerLength, (m_headerLength / 4));

		auto dscp = m_differServ & 0xFFFFFF00;

		auto ecn = m_differServ & 0x000000FF;

		m_texts["differServ"] = std::format("   Differentiated Services Field: {}, (DSCP: {}, ECN: {})", m_differServ, ProtocolCatalog::dscpMap[dscp], ProtocolCatalog::ecnMap[ecn]);

		std::bitset<6> dscpBits;
		for (int i = 0; i < 6; i++) {
			dscpBits[i] = (m_differServ >> i) & 1;
		}

		std::bitset<2> ecnBits;
		for (int i = 0; i < 2; i++) {
			ecnBits[i] = (m_differServ >> (6 + i)) & 1;
		}

		m_texts["DSCP"] = std::format("\t\t{} . . = Differentiated Services Codepoint: {} ({})", formatBitSet(dscpBits.to_string()), ProtocolCatalog::dscpMap[dscp], dscp);

		m_texts["ECN"] = std::format("\t\t. . . .  . . {} = Explicit Congestion Notification: {} ({})", ecnBits.to_string(), ProtocolCatalog::ecnMap[ecn], ecn);

		m_texts["ID"] = std::format("\tIdentification: 0x{:x} ({})", m_identification, m_identification);

		std::bitset<3> flagBits;
		for (int i = 0; i < 3; i++) {
			flagBits[i] = (m_flags >> (5 + i)) & 1;
		}

		m_texts["IPFlags"] = std::format("   {} .  . . . . = Flags: 0x{:x}", flagBits.to_string(), flagBits.to_ulong());

		m_texts["resBits"] = std::format("\t\t   {} . . .  . . . . = Reserved bit: {}", (int)flagBits[0], (int)flagBits[0] ? "Set" : "Not Set");
		m_texts["dfBits"] = std::format("\t\t   . {} . .  . . . . = Don't Fragment: {}", (int)flagBits[1], (int)flagBits[1] ? "Set" : "Not Set");
		m_texts["mfBits"] = std::format("\t\t   . . {} .   . . . . = More Fragments: {}", (int)flagBits[2], (int)flagBits[2] ? "Set" : "Not Set");

		std::bitset<13> fragBits;
		for (int i = 0; i < 13; i++) {
			fragBits[i] = (m_fragmentationOffset >> i) & 1;
		}

		m_texts["offset"] = std::format("\t. . . {}  {} = Fragmentation Offset: {}", fragBits.to_string().at(0), formatBitSet(fragBits.to_string().substr(1, 12)), m_fragmentationOffset);

		std::string prot = "Unknown";

		switch (m_proto) {
		case IPPROTO_TCP:
			prot = "TCP";
			break;
		case IPPROTO_UDP:
			prot = "UDP";
			break;
		case IPPROTO_IGMP:
			prot = "IGMP";
			break;
		case IPPROTO_ICMP:
			prot = "ICMP";
			break;
		}

		m_texts["proto"] = std::format("\tProtocol: {} ({})", prot, m_proto);

		m_texts["IPChecksum"] = std::format("\tHeader Checksum: 0x{:x}", m_headerChecksum);

		m_texts["src"] = std::format("\tSource Address: {}", m_srcAddr);

		m_texts["dest"] = std::format("\tDestination Address: {}", m_destAddr);

		if (m_IPoptionsCount > 0) {
			std::stringstream ss;

			ss << "   Options: (" << m_optSize << " bytes): ";

			for (size_t i = 0; i < m_IPoptionsCount; i++) {
				ss << m_opts.at(i)->m_name << ", ";
			}

			m_texts["optStr"] = ss.str();
		}

		for (size_t i = 0; i < m_IPoptionsCount; i++) {
			auto* o = m_opts.at(i).get();
			m_ipOptTexts.push_back(std::format("\t   IP Option - {} ({} bytes): {}", o->m_name, o->m_length, o->m_value));
		}
	}

	return m_texts;
}

// used for the hop map
// just gets the packet address that isn't the user's ip
std::string IPV4::getAlienAddr() {
	const bool sourcePublic = isPublicIPv4(m_srcAddr);
	const bool destinationPublic = isPublicIPv4(m_destAddr);
	if (sourcePublic != destinationPublic) {
		return sourcePublic ? m_srcAddr : m_destAddr;
	}
	if (m_srcAddr == SDK::ipAddress) {
		return m_destAddr;
	}
	if (m_destAddr == SDK::ipAddress) {
		return m_srcAddr;
	}
	// When both sides have the same scope, prefer the destination. This matches
	// the common outbound-capture case even if adapter discovery was imperfect.
	return m_destAddr;
}
