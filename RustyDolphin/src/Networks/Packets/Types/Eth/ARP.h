#pragma once

#include "Packet.h"

class ARP : public Packet {
public:
	int hardType;
	int protoType;
	int hardSize;
	int protoSize;
	int opcode;
	std::string sendMAC;
	std::string sendAddr;
	std::string targetMAC;
	std::string targetAddr;

	ARP(pcap_pkthdr* header, const u_char* pkt_data);

	std::string toString() override;
};