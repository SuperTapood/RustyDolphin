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

enum class FilterFlag {
	Unfiltered,
	Passed,
	Failed
};

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
	std::map<std::string, std::string> m_properties;

	FilterFlag m_flag = FilterFlag::Unfiltered;

	Packet(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx);
	virtual ~Packet();

	virtual void render() {
		Renderer::render(this);
	}

	virtual void renderExpanded() {
		Renderer::renderExpanded(this);
	}

	// these aren't really used for anything other than debugging and hopefully compiled out :)
	virtual std::string toString();
	virtual json jsonify();

	// this is used to generate the texts needed for renderExpanded when they are needed, not when the packet is created
	// this saves A LOT of time when processing packets
	virtual std::map<std::string, std::string> getTexts();

	// functions to hopefully both optimize and obfuscate the way data is parsed from the packet data
	std::string parseMAC();
	std::string parseIPV4();
	std::string parseIPV6();
	std::string parse(unsigned long long size);
	long long parseLongLong();
	long parseLong();
	int parseInt();
	short parseShort();
	char parseChar();

	// helper function to seperate the bits in a more nice looking way (groups of 4)
	std::string formatBitSet(std::string bits);

	int getPos() const {
		return m_pos;
	}

protected:
	std::map<std::string, std::string> m_texts;

private:
	unsigned int m_pos = 0;

	// packet-only helper functions
	std::string padDate(int t);
	uint64_t htonll(uint64_t x);
	int htoni(int x);
};