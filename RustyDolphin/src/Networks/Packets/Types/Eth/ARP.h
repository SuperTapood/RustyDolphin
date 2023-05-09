#pragma once

#include "Packet.h"

class ARP : public Packet {
public:
	unsigned short m_hardType;
	unsigned short m_protoType;
	unsigned short m_hardSize;
	unsigned short m_protoSize;
	unsigned short m_opcode;
	std::string m_sendMAC;
	std::string m_sendAddr;
	std::string m_targetMAC;
	std::string m_targetAddr;

	std::string m_ARPTitle;
	std::string m_hardStr;
	std::string m_protoStr;
	std::string m_codeStr;

	ARP(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx);

	std::string toString() override;
	json jsonify() override;

	void render() override {
		Renderer::render(this);
	}

	void renderExpanded() override {
		Renderer::renderExpanded(this);
	}
};