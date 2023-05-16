#include "IPV6.h"

#include <sstream>
#include "../../../../GUI/Renderer.h"
#include <bitset>
#include "../../../../Base/Data.h"
#include <format>

IPV6::IPV6(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx) : Packet(header, pkt_data, idx) {
	auto thingy = parseLong();
	m_trafficCls = thingy & 4080;

	m_flowLabel = thingy & 1048575;

	m_payloadLength = parseShort();

	m_nextHeader = parseChar();

	m_hopLimit = parseChar();

	m_srcAddr = parseIPV6();

	m_destAddr = parseIPV6();

	if (m_nextHeader == IPPROTO_HOPOPTS) {
		m_options.push_back(new HopByHop(this));
	}

	m_expands.insert({ "IPV6 Title", false });
	m_expands.insert({ "Traffic Class", false });

	Packet::m_strType = "IPV6";
}

std::string IPV6::toString() {
	std::stringstream ss;

	ss << "IPV6 Packet at " << m_texts["time"] << " of length " << m_payloadLength << " from " << m_srcAddr << " to " << m_destAddr << "of payload length: " << m_payloadLength << " transfer protocol is " << m_nextHeader << "\n";

	return ss.str();
}

json IPV6::jsonify() {
	auto j = Packet::jsonify();

	j["IPV6"] = "start";
	j["Version"] = m_version;
	j["Traffic Class"] = m_trafficCls;
	j["Flow Label"] = m_flowLabel;
	j["Payload Length"] = m_payloadLength;
	j["Protocol"] = m_nextHeader;
	j["Hop Limit"] = m_hopLimit;
	j["Source Address"] = m_srcAddr;
	j["Destination Address"] = m_destAddr;
	j["Header Length"] = m_headerLength;

	/*if (m_options.size() > 0) {
		j["option"] = m_options.at(0).toString();
	}*/

	return j;
}

std::map<std::string, std::string> IPV6::getTexts() {
	if (m_texts.empty()) {
		Packet::getTexts();

		m_texts["IPV6 Title"] = std::format("Internet Protocol Version 6, Src: {}, Dst: {}", m_srcAddr, m_destAddr);

		std::bitset<8> trafficCls;
		for (int i = 0; i < 2; i++) {
			trafficCls[i] = (m_trafficCls >> i) & 1;
		}

		std::bitset<6> dscpBits;
		for (int i = 0; i < 6; i++) {
			dscpBits[i] = (m_trafficCls >> i) & 1;
		}

		std::bitset<2> ecnBits;
		for (int i = 0; i < 2; i++) {
			ecnBits[i] = (m_trafficCls >> (6 + i)) & 1;
		}

		m_texts["Traffic Class"] = std::format("   .... {} .... .... .... .... .... = Traffic Class 0x{:x} (DSCP: {}, ECN: {})", trafficCls.to_string(), m_trafficCls, Data::dscpMap[dscpBits.to_ulong()], Data::ecnMap[ecnBits.to_ulong()]);

		m_texts["DSCP"] = std::format("\t\t.... {}.. .... .... .... .... .... = Differentiated Services Codepoint: {} ({})", dscpBits.to_string(), Data::dscpMap[dscpBits.to_ulong()], dscpBits.to_ulong());

		m_texts["ECN"] = std::format("\t\t.... .... ..{} .... .... .... .... = Explicit Congestion Notification: {} ({})", ecnBits.to_string(), Data::ecnMap[ecnBits.to_ulong()], ecnBits.to_ulong());

		std::bitset<20> flowBits;
		for (int i = 0; i < 2; i++) {
			flowBits[i] = (m_flowLabel >> i) & 1;
		}

		m_texts["Flow Label"] = std::format("\t.... {} = Flow Label: 0x{:x}", flowBits.to_string(), m_flowLabel);

		m_texts["Payload Length"] = std::format("\tPayload Length: {}", m_payloadLength);

		std::string nextHeader;

		switch ((int)m_nextHeader) {
		case IPPROTO_HOPOPTS:
			nextHeader = "IPv6 Hop-by-Hop Option (0)";
			break;
		case IPPROTO_TCP:
			nextHeader = "TCP (6)";
			break;
		case IPPROTO_UDP:
			nextHeader = "UDP (17)";
			break;
		case IPPROTO_ICMPV6:
			nextHeader = "ICMPv6 (58)";
			break;
		default:
			nextHeader = std::format("Unknown ({})", (int)m_nextHeader);
			break;
		}

		m_texts["Next Header"] = std::format("\tNext Header: {}", nextHeader);

		m_texts["Hop Limit"] = std::format("\tHop Limit: {}", (int)m_hopLimit);

		m_texts["IPV6 Source"] = std::format("\tSource Address: {}", m_srcAddr);

		m_texts["IPV6 Destination"] = std::format("\tDestination Address: {}", m_destAddr);

		if (m_options.size() > 0) {
			m_expands.insert({ "IPV6 Option Title", false });
			m_texts["IPV6 Option Title"] = std::format("   IPV6 Hop-by-Hop Option");
			auto option = (HopByHop*)m_options.at(0);

			auto nh = option->m_nextHeader;

			switch ((int)nh) {
			case IPPROTO_TCP:
				nextHeader = "TCP (6)";
				break;
			case IPPROTO_UDP:
				nextHeader = "UDP (17)";
				break;
			case IPPROTO_ICMPV6:
				nextHeader = "ICMPv6 (58)";
				break;
			default:
				nextHeader = std::format("Unknown ({})", (int)m_nextHeader);
				break;
			}

			m_texts["IPV6 Option Next Header"] = std::format("\t\tNext Header: {}", nextHeader);
			m_texts["IPV6 Option Length"] = std::format("\t\tLength: {} ({})", option->m_length, option->m_length + 8);

			for (auto o : option->m_options) {
				m_ipOptTexts.push_back(std::format("\t\t{} (0x{:x}) Length: {}, Data: {}", Data::hopMap[o.m_type], o.m_type, o.m_length, o.m_data));
			}
		}
	}

	return m_texts;
}
