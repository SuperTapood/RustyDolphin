#pragma once

#include "../../Eth/Packet.h"
#include "../../IP/IP.h"
#include "../../src/Win/SDK.h"

template <typename IPVersion>
class UDP : public IPVersion {
	static_assert(std::is_base_of_v<Packet, IPVersion>,
		"IPVersion must inherit from Packet");
public:
	short m_srcPort;
	short m_destPort;
	short m_length;
	short m_UDPChecksum;
	int m_payloadLength;
	std::string m_payload;
	std::string m_process;

	UDP(pcap_pkthdr* header, const u_char* pkt_data) : IPVersion(header, pkt_data) {
		m_srcPort = IPVersion::parseShort();

		m_destPort = IPVersion::parseShort();

		m_length = IPVersion::parseShort();

		m_UDPChecksum = IPVersion::parseShort();

		m_payloadLength = m_length - 8;

		m_payload = IPVersion::parse(m_payloadLength);

		if constexpr (std::is_same_v<IPVersion, IPV4>) {
			if (IPVersion::m_srcAddr == SDK::ipAddress) {
				m_process = SDK::getProcFromPort(m_srcPort);
			}
			else {
				m_process = SDK::getProcFromPort(m_destPort);
			}
		}
		else if constexpr (std::is_same_v<IPVersion, IPV4>) {
			m_process = SDK::getProcFromPort(m_srcPort);
			if (m_process.at(0) == '<' && m_process.at(m_process.size() - 1) == '>') {
				m_process = SDK::getProcFromPort(m_destPort);
			}
		}
	}

	std::string toString() override {
		std::stringstream ss;

		ss << "UDPV4 Packet at " << IPVersion::m_time << " from " << IPVersion::m_srcAddr << " at port " << m_srcPort << " to " << IPVersion::m_destAddr << " at port " << m_destPort;

		ss << ". Proccess = " << m_process << "\n";

		return ss.str();
	}

	json jsonify() override {
		auto j = IPVersion::jsonify();

		j["UDPV4"] = "start";
		j["Source Port"] = m_srcPort;
		j["Destination Port"] = m_destPort;
		j["UDP Length"] = m_length;
		j["UDP Checksum"] = m_UDPChecksum;
		j["Payload Length"] = m_payloadLength;
		j["Payload"] = m_payload;

		return j;
	}
};