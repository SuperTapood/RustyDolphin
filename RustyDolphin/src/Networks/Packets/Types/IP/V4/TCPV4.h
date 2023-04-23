#pragma once

#include "IPV4.h"

class TCPV4 : public IPV4 {
public:
	int srcPort;
	int destPort;
	long long seqNum;
	long long ackNum;
	int TCPLength;
	int TCPflags;
	int window;
	int TCPchecksum;
	int urgentPtr;

	int optionCount;
	TCPOption** options;

	TCPV4(pcap_pkthdr* header, const u_char* pkt_data);
	std::string toString() override;
	json jsonify() override;
};