#pragma once

#include <ctime>
#include <WinSock2.h>
#include <pcap.h>
#include <string>
#include <json.hpp>
#include <imgui.h>
#include <GLFW/glfw3.h>
#include <map>

#include "../../../../GUI/Renderer.h"

using json = nlohmann::ordered_json;

// *slaps roof of class* this bad boy can fit so many fcking members in it
class Packet {
public:
	unsigned int m_idx;
	std::string m_idxStr;
	std::string m_description;
	std::map<std::string, bool> m_expands;
	std::string m_title;
	std::string m_hexData;

	unsigned int pos = 0;
	// header stuff
	std::string m_time;
	long double m_epoch;
	unsigned int m_len;

	// ether stuff
	std::string m_phyDst;
	std::string m_phySrc;
	unsigned short m_type;
	std::string m_strType;
	const u_char* m_pktData;

	Packet(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx);
	virtual ~Packet() = default;

	virtual void render() {
		Renderer::render(this);
	}

	virtual void renderExpanded() {
		Renderer::renderExpanded(this);
	}

	virtual std::string toString();
	virtual json jsonify();

protected:

	std::string parseMAC(unsigned int size = 6);
	std::string parseIPV4(unsigned int size = 4);
	std::string parseIPV6(unsigned int size = 16);
	std::string parse(unsigned long long size);
	long long parseLongLong();
	long parseLong();
	int parseInt();
	short parseShort();

private:
	std::string padDate(int t);
	uint64_t htonll(uint64_t x);
	int htoni(int x);
};