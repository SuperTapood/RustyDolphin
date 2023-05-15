#pragma once

#include "../Eth/Packet.h"
#include "IPV4Options/IPV4Options.h"

class IPV4 : public Packet {
public:
	unsigned char m_version = 4;
	unsigned char m_headerLength;
	unsigned char m_differServ;
	unsigned short m_totalLength;
	unsigned short m_identification;
	unsigned char m_flags;
	unsigned int m_fragmentationOffset;
	unsigned char m_ttl;
	unsigned char m_proto;
	unsigned short m_headerChecksum;
	std::string m_srcAddr;
	std::string m_destAddr;
	unsigned int m_IPoptionsCount;
	std::vector<IPV4Option*> m_opts;

	std::vector<std::string> m_ipOptTexts;
	long m_optSize;

	IPV4(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx);
	~IPV4() override = default;

	std::string toString() override;
	json jsonify() override;

	virtual void render() override {
		Renderer::render(this);
	}

	virtual void renderExpanded() override {
		Renderer::renderExpanded(this);
	}

	virtual std::map<std::string, std::string> getTexts() override;
};