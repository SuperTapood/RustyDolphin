#pragma once

#include "../../Eth/Packet.h"
#include "../../TCPOptions/TCPOption.h"
#include "IPV4Options/IPV4Options.h"

class IPV4 : public Packet {
public:
	int m_headerLength;
	int m_differServ;
	int m_totalLength;
	int m_identification;
	int m_flags;
	int m_fragmentationOffset;
	int m_ttl;
	int m_proto;
	int m_headerChecksum;
	std::string m_srcAddr;
	std::string m_destAddr;
	int m_IPoptionsCount;
	IPV4Option* m_opts;

	IPV4(pcap_pkthdr* header, const u_char* pkt_data);
	~IPV4() override = default;

	std::string toString() override;
	json jsonify() override;
};