#pragma once

#include "../../Eth/Packet.h"
#include "../../IP/IP.h"
#include "../../src/Win/SDK.h"
#include "../../../../../GUI/Renderer.h"

template <typename IPVersion>
class UDP : public IPVersion {
	static_assert(std::is_base_of_v<Packet, IPVersion>,
		"IPVersion must inherit from Packet");
public:
	unsigned short m_srcPort;
	unsigned short m_destPort;
	unsigned short m_length;
	short m_UDPChecksum;
	unsigned int m_payloadLength;
	std::string m_payload;
	std::string m_process;

	UDP(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx) : IPVersion(header, pkt_data, idx) {
		m_srcPort = Packet::parseShort();

		m_destPort = Packet::parseShort();

		m_length = Packet::parseShort();

		m_UDPChecksum = Packet::parseShort();

		m_payloadLength = m_length - 8;

		m_payload = Packet::parse(m_payloadLength);

		/*if constexpr (std::is_same_v<IPVersion, IPV4>) {
			if (IPVersion::m_srcAddr == SDK::ipAddress) {
				m_process = SDK::getProcFromPort(m_srcPort);
			}
			else {
				m_process = SDK::getProcFromPort(m_destPort);
			}
		}
		else if constexpr (std::is_same_v<IPVersion, IPV6>) {
			m_process = SDK::getProcFromPort(m_srcPort);
			if (m_process.at(0) == '<' && m_process.at(m_process.size() - 1) == '>') {
				m_process = SDK::getProcFromPort(m_destPort);
			}
		}*/

		m_process = SDK::getProcFromPort(m_srcPort);
		if (m_process.at(0) == '<' && m_process.at(m_process.size() - 1) == '>') {
			m_process = SDK::getProcFromPort(m_destPort);
		}

		Packet::m_strType = "UDP (" + Packet::m_strType + ")";
		std::stringstream ss;
		ss << "(" << m_process << ") " << m_srcPort << " -> " << m_destPort << " payload length = " << m_payloadLength;
		Packet::m_description = ss.str();
	}

	std::string toString() override {
		std::stringstream ss;

		ss << "UDPV4 Packet at " << Packet::m_texts["time"] << " from " << IPVersion::m_srcAddr << " at port " << m_srcPort << " to " << IPVersion::m_destAddr << " at port " << m_destPort;

		ss << ". Proccess = " << m_process << "\n";

		return ss.str();
	}

	json jsonify() override {
		auto j = IPVersion::jsonify();

		j["UDP"] = "start";
		j["Source Port"] = m_srcPort;
		j["Destination Port"] = m_destPort;
		j["UDP Length"] = m_length;
		j["UDP Checksum"] = m_UDPChecksum;
		j["Payload Length"] = m_payloadLength;
		j["Payload"] = m_payload;

		return j;
	}

	void render() override {
		Renderer::render(this);
	}
};