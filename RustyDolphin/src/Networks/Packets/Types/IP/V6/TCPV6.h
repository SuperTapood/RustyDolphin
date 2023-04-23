#pragma once

#include "IPV6.h"

#include "../../TCPOptions/TCPOptions.h"

class TCPV6 : public IPV6 {
public:
	int srcPort;
	int destPort;
	long seqNum;
	long ackNum;
	int TCPLength;
	int TCPflags;
	int window;
	int TCPchecksum;
	int urgentPtr;

	int optionCount;
	TCPOption** options;

	TCPV6(pcap_pkthdr* header, const u_char* pkt_data);
	std::string toString() override;
	json jsonify() override;
};