#pragma once

#include "../Eth/Packet.h"
#include "IPV4Options/IPV4Options.h"

class IPV4 : public Packet {
public:
	char m_version = 4;
	char m_headerLength;
	char m_differServ;
	short m_totalLength;
	short m_identification;
	char m_flags;
	int m_fragmentationOffset;
	char m_ttl;
	char m_proto;
	short m_headerChecksum;
	std::string m_srcAddr;
	std::string m_destAddr;
	int m_IPoptionsCount;
	IPV4Option* m_opts;

	IPV4(pcap_pkthdr* header, const u_char* pkt_data);
	~IPV4() override = default;

	std::string toString() override;
	json jsonify() override;
};