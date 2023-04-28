#pragma once

#include "IPV4.h"
#include <pcap.h>
#include <uchar.h>

class ICMPV4 : public IPV4 {
public:
	unsigned short m_ICMPtype;
	unsigned short m_code;
	unsigned short m_ICMPChecksum;
	unsigned short m_indentifierBE;
	unsigned short m_indentifierLE;
	unsigned short m_seqNumberBE;
	unsigned short m_seqNumberLE;
	unsigned long long m_ROHLength;
	std::string m_restOfHeader;

	ICMPV4(pcap_pkthdr* header, const u_char* pkt_data);
	std::string toString() override;
	json jsonify() override;
};