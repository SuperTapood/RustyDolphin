#pragma once

#include "Packet.h"

class ARP : public Packet {
public:
	int m_hardType;
	int m_protoType;
	int m_hardSize;
	int m_protoSize;
	int m_opcode;
	std::string m_sendMAC;
	std::string m_sendAddr;
	std::string m_targetMAC;
	std::string m_targetAddr;

	ARP(pcap_pkthdr* header, const u_char* pkt_data);

	std::string toString() override;
	json jsonify() override;
};