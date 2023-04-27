#pragma once

#include "IPV6.h"

#include "../../TCPOptions/TCPOptions.h"

class TCPV6 : public IPV6 {
public:
	int m_srcPort;
	int m_destPort;
	long m_seqNum;
	long m_ackNum;
	int m_TCPLength;
	int m_TCPflags;
	int m_window;
	int m_TCPchecksum;
	int m_urgentPtr;

	int m_optionCount;
	TCPOption** m_options;

	TCPV6(pcap_pkthdr* header, const u_char* pkt_data);
	std::string toString() override;
	json jsonify() override;
};