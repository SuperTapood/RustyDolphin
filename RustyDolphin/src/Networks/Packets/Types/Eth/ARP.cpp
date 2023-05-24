#include "ARP.h"

#include <sstream>
#include "../../../../GUI/Renderer.h"
#include "../../../../Base/Data.h"
#include <iostream>

constexpr auto ETHERTYPE_IPV4 = 0x0800;
constexpr auto ETHERTYPE_IPV6 = 0x86DD;

ARP::ARP(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx) : Packet(header, pkt_data, idx) {
	m_hardType = parseShort();

	m_protoType = parseShort();

	m_hardSize = parseChar();

	m_protoSize = parseChar();

	m_opcode = parseShort();

	m_sendMAC = parseMAC();

	m_sendAddr = parseIPV4();

	m_targetMAC = parseMAC();

	m_targetAddr = parseIPV4();

	Packet::m_strType = "ARP";

	std::stringstream ss;

	if (m_opcode == 1) {
		ss << "who is " << m_targetAddr << "? Tell " << m_sendAddr;
	}
	else if (m_opcode == 2) {
		ss << m_sendAddr << " is at physical address " << m_sendMAC;
	}
	else {
		ss << "unknown opcode " << m_opcode;
	}

	ss << "\n";

	m_description = ss.str();

	m_expands.insert({ "ARP Title", false });

	m_properties.insert({ "ip", "arp" });
	m_properties.insert({ "saddr", m_sendMAC });
	m_properties.insert({ "daddr", m_targetMAC });
}

std::string ARP::toString() {
	std::stringstream ss;

	ss << "ARP Packet at " << m_texts["time"];

	if (m_opcode == 1) {
		ss << " who is " << m_targetAddr << "? Tell " << m_sendAddr;
	}
	else if (m_opcode == 2) {
		ss << " " << m_sendAddr << " is at physical address " << m_sendMAC;
	}
	else {
		ss << " unknown opcode " << m_opcode;
	}

	ss << "\n";

	return ss.str();
}

json ARP::jsonify() {
	auto j = Packet::jsonify();

	j["ARP"] = "start";
	j["hardware type"] = m_hardType;
	j["protocol type"] = m_protoType;
	j["hardware size"] = m_hardSize;
	j["protocol size"] = m_protoSize;
	j["operation code"] = m_opcode;
	j["sender MAC Address"] = m_sendMAC;
	j["sender IP Address"] = m_sendAddr;
	j["target MAC Address"] = m_targetMAC;
	j["target IP Address"] = m_targetAddr;

	return j;
}

std::map<std::string, std::string> ARP::getTexts() {
	if (m_texts.empty()) {
		Packet::getTexts();

		if (m_opcode < Data::arpCodes.size()) {
			m_texts["opcode"] = Data::arpCodes.at(m_opcode);
		}
		else {
			m_texts["opcode"] = "unknown";
		}

		m_texts["arpTitle"] = std::format("Address Resolution Protocol ({})", m_texts["opcode"]);

		m_texts["hardType"] = std::format("Ethernet ({})", std::to_string(m_hardType));

		if (m_hardType < Data::arpHard.size()) {
			m_texts["hardType"] = std::format("{} ({})", Data::arpHard.at(m_hardType), std::to_string(m_hardType));
		}
		else if (m_hardType == 256) {
			m_texts["hardType"] = "HW_EXP2 (256)";
		}
		else if (m_hardType == 257) {
			m_texts["hardType"] = "AEthernet (257)";
		}
		else {
			m_texts["hardType"] = std::format("Unknown {}", m_hardType);
		}

		switch (m_protoType) {
		case (ETHERTYPE_IPV4):
			m_texts["protoType"] = "IPV4 (0x0800)";
			break;
		case (ETHERTYPE_IPV6):
			m_texts["protoType"] = "IPV6 (0x86DD)";
			break;
		default:
			m_texts["protoType"] = "Unknown";
			break;
		}

		m_texts["code"] = std::format("{} ({})", m_texts["opcode"], m_opcode);
	}

	return m_texts;
}