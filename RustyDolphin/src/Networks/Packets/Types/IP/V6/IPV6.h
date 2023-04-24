#pragma once

#include "../../Eth/Packet.h"

#include <pcap.h>

class IPV6 : public Packet {
public:
	int version;
	int trafficCls;
	long flowLabel;
	long payloadLength;
	int proto;
	int hopLimit;
	std::string srcAddr;
	std::string destAddr;
	int headerLength = 40;

	IPV6(pcap_pkthdr* header, const u_char* pkt_data);
	~IPV6() override = default;

	std::string toString() override;
	json jsonify() override;
};