#pragma once

#include "../../Eth/Packet.h"
#include "../../TCPOptions/TCPOption.h"
#include "IPV4Options/IPV4Options.h"

class IPV4 : public Packet {
public:
	int headerLength;
	int differServ;
	int totalLength;
	int identification;
	int flags;
	int fragmentationOffset;
	int ttl;
	int proto;
	int headerChecksum;
	std::string srcAddr;
	std::string destAddr;
	int IPoptionsCount;
	IPV4Option* opts;

	IPV4(pcap_pkthdr* header, const u_char* pkt_data);

	std::string toString() override;
};