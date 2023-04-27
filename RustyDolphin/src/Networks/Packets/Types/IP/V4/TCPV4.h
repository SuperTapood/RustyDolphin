#pragma once

#include "IPV4.h"

class TCPV4 : public IPV4 {
public:
	int m_srcPort;
	int m_destPort;
	long long m_seqNum;
	long long m_ackNum;
	int m_TCPLength;
	int m_TCPflags;
	int m_window;
	int m_TCPchecksum;
	int m_urgentPtr;

	int m_optionCount;
	TCPOption** m_options;

	TCPV4(pcap_pkthdr* header, const u_char* pkt_data);
	std::string toString() override;
	json jsonify() override;
};