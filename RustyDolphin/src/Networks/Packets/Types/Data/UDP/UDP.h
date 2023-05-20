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

		Packet::m_expands.insert({ "UDP Title", false });

		Packet::m_properties.insert({ "proto", "udp" });
		Packet::m_properties.insert({ "sport", std::to_string(m_srcPort)});
		Packet::m_properties.insert({ "dport", std::to_string(m_destPort) });
		Packet::m_properties.insert({ "proc", m_process });
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

	void renderExpanded() override {
		Renderer::renderExpanded(this);
	}

	std::map<std::string, std::string> getTexts() {
		if (Packet::m_texts.empty()) {
			IPVersion::getTexts();

			Packet::m_texts["UDP Title"] = std::format("User Datagram Protocol, Src Port: {}, Dst Port: {}", m_srcPort, m_destPort);

			Packet::m_texts["UDP SPort"] = std::format("\tSource Port: {}", m_srcPort);

			Packet::m_texts["UDP DPort"] = std::format("\tDestination Port: {}", m_destPort);

			Packet::m_texts["UDP Length"] = std::format("\tLength: {}", m_length);

			Packet::m_texts["UDP Checksum"] = std::format("\tChecksum: {:x}", m_UDPChecksum);

			Packet::m_texts["UDP Payload Length"] = std::format("\tUDP Payload Length: {}", m_payloadLength);

			Packet::m_texts["UDP Payload"] = std::format("\tUDP Payload: {}", m_payload);
		}

		return Packet::m_texts;
	}
};