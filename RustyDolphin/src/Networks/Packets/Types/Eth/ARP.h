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

	ARP(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx);

	std::string toString() override;
	json jsonify() override;
	void render() override;
};