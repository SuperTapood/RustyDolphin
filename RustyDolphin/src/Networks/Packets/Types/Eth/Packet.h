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

// *slaps roof of class* this bad boy can fit so many members in it
class Packet {
public:
	unsigned int m_idx;
	std::string m_idxStr;
	std::string m_description;
	static std::map<std::string, bool> m_expands;

	// header stuff
	long double m_epoch;
	unsigned int m_len;

	// ether stuff
	std::string m_phyDst;
	std::string m_phySrc;
	unsigned short m_type;
	std::string m_strType;
	u_char* m_pktData;
	pcap_pkthdr* m_header;

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

	virtual std::map<std::string, std::string> getTexts();

	std::string parseMAC();
	std::string parseIPV4();
	std::string parseIPV6();
	std::string parse(unsigned long long size);
	long long parseLongLong();
	long parseLong();
	int parseInt();
	short parseShort();
	char parseChar();
	std::string formatBitSet(std::string bits);

	int getPos() const {
		return m_pos;
	}

protected:
	std::map<std::string, std::string> m_texts;

private:
	unsigned int m_pos = 0;
	std::string padDate(int t);
	uint64_t htonll(uint64_t x);
	int htoni(int x);
};