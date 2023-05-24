#include "Packet.h"
#include <iostream>
#include <sstream>
#include <memory>
#include <string>
#include <json.hpp>
#include <pcap.h>
#include <iostream>
#include <sstream>
#include <ctime>
#include <WinSock2.h>
#include <regex>
#include <format>
#include <chrono>

#include "../../../../Win/SDK.h"
#include "../../../../Base/Data.h"

std::map<std::string, bool> Packet::m_expands;

Packet::Packet(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx) {
	this->m_idx = idx;

	// table indices are 1 indexed
	m_idxStr = std::to_string(idx + 1);

	m_len = header->caplen;

	m_pktData = new u_char[m_len];

	// we need a copy of the packet data for the hex data view (and need to do this like this because pkt_data isn't really _ours_)
	std::copy(pkt_data, pkt_data + m_len, m_pktData);

	// same with the header, we just borrow them for a hot sec
	m_header = new pcap_pkthdr(*header);

	if (!Data::fileAdapter) {
		auto now = std::chrono::system_clock::now();
		auto duration = now.time_since_epoch();
		auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(duration);
		m_epoch = (long double)nanoseconds.count() / 1e9;

		header->ts.tv_sec = (int)m_epoch;
		header->ts.tv_usec = (long)(m_epoch - ((int)m_epoch)) * 1e6;
	}
	else {
		m_epoch = ((double)header->ts.tv_sec + (double)header->ts.tv_usec / 1e6);
	}

	m_phyDst = parseMAC();

	m_phySrc = parseMAC();

	m_type = parseShort();

	m_description = "base packet";

	m_expands.insert({ "Packet Title", false });

	m_properties.insert({ "len", std::to_string(m_len) });
	m_properties.insert({ "num", m_idxStr });
}

Packet::~Packet() {
	delete[] m_pktData;
	delete m_header;
	m_properties.clear();
}

std::string Packet::toString() {
	std::stringstream ss;

	ss << "Base Packet at " << m_texts["time"] << " of len " << m_len << " type: " << m_type << " from " << m_phySrc << " to " << m_phyDst << "\n";

	return ss.str();
}

json Packet::jsonify() {
	json j = {
		{"header", "start"},
		{"time", m_texts["time"]},
		{"epoch", m_epoch},
		{"len", m_len},
		{"base packet", "start"},
		{"physical destination", m_phyDst},
		{"physical source", m_phySrc},
		{"packet type", m_type},
	};

	return j;
}

std::string Packet::padDate(int t) {
	std::stringstream ss;
	ss << t;
	auto s = ss.str();

	if (s.length() < 2) {
		return "0" + s;
	}

	return s;
}

std::string Packet::parseMAC() {
	constexpr auto size = 6;
	std::stringstream ss;
	std::string mac;

	for (int i = m_pos + size; m_pos < i; m_pos++) {
		ss << std::setfill('0') << std::setw(2) << std::hex << (int)m_pktData[m_pos] << ":";
	}

	mac = ss.str();
	mac.pop_back();

	return mac;
}

std::string Packet::parseIPV4() {
	constexpr auto size = 4;
	std::stringstream ss;
	std::string ip;

	for (int i = m_pos + size; m_pos < i; m_pos++) {
		ss << (int)m_pktData[m_pos] << ".";
	}

	ip = ss.str();
	ip.pop_back();

	return ip;
}

std::string Packet::parseIPV6() {
	constexpr auto size = 16;
	std::stringstream ss;
	std::string ip;

	for (int i = m_pos + size; m_pos < i; m_pos += 2) {
		if ((int)m_pktData[m_pos] == 0 && (int)m_pktData[m_pos + 1] == 0) {
			ss << ":";
			continue;
		}
		ss << std::setfill('0') << std::setw(2) << std::hex << (int)m_pktData[m_pos] << std::setfill('0') << std::setw(2) << std::hex << (int)m_pktData[m_pos + 1] << ":";
	}

	ip = ss.str();
	ip.pop_back();

	return ip;
}

std::string Packet::parse(unsigned long long size) {
	std::string result;
	result.reserve(size * 2); // each byte is 2 hex

	for (int end = m_pos + size; m_pos < end; m_pos++) {
		char buf[3];
		sprintf_s(buf, "%02x", (int)m_pktData[m_pos]); // fun isn't it
		result.append(buf);
	}

	return result;
}

uint64_t Packet::htonll(uint64_t x) {
	if (htonl(1) == 1) {
		// The system is already in network byte order
		return x;
	}
	else {
		// Swap the bytes
		return ((uint64_t)htonl(x & 0xFFFFFFFF) << 32) | htonl(x >> 32);
	}
}

int Packet::htoni(int x) {
	if (htons(1) == 1) {
		// The system is already in network byte order
		return x;
	}
	else {
		// Swap the bytes
		return ((int)htons(x & 0xFFFFFFFF) << 16) | htons(x >> 16);
	}
}

long long Packet::parseLongLong() {
	long long out;

	constexpr auto len = 8;

	// using memcpy and converting the network host byte order headache is just faster than using bitshifts
	std::memcpy(&out, m_pktData + m_pos, len);

	m_pos += len;

	return htonll(out);
}

long Packet::parseLong() {
	long out;

	constexpr auto len = 4;

	std::memcpy(&out, m_pktData + m_pos, len);

	m_pos += len;

	return htonl(out);
}

int Packet::parseInt() {
	int out;

	constexpr auto len = 4;

	std::memcpy(&out, m_pktData + m_pos, len);

	m_pos += len;

	return htoni(out);
}

short Packet::parseShort() {
	short out;

	constexpr auto len = 2;

	std::memcpy(&out, m_pktData + m_pos, len);

	m_pos += len;

	return htons(out);
}

char Packet::parseChar() {
	char out;

	constexpr auto len = 1;

	std::memcpy(&out, m_pktData + m_pos, len);

	m_pos += len;

	return out;
}

std::map<std::string, std::string> Packet::getTexts() {
	if (m_texts.empty()) {
		struct tm timeinfo;
		time_t epoch_t = static_cast<time_t>(m_epoch);
		localtime_s(&timeinfo, &epoch_t);
		std::stringstream ss;
		int year = 1900 + timeinfo.tm_year;
		auto month = padDate(1 + timeinfo.tm_mon);
		auto day = padDate(timeinfo.tm_mday);
		auto hour = padDate(timeinfo.tm_hour);
		auto min = padDate(timeinfo.tm_min);
		auto sec = padDate(timeinfo.tm_sec);

		m_texts["time"] = std::format("{}/{}/{} {}:{}:{}", year, month, day, hour, min, sec);

		m_texts["title"] = std::format("Frame {}: {} bytes on wire ({} bits)", m_idx + 1, m_len, (m_len * 8));

		std::string result;
		result.reserve(m_len * 2);

		for (int i = 0; i < m_len; i++) {
			char buf[3];
			sprintf_s(buf, "%02x", (int)m_pktData[i]);
			result.append(buf);
		}

		m_texts["hexData"] = result;

		auto src1 = m_phySrc.substr(0, 8);
		auto src2 = m_phySrc.substr(9, 8);

		m_texts["macSrc"] = std::format("\tSource: {}{} ({})", SDK::lookupMAC(src1), src2, m_phySrc);

		auto dst1 = m_phyDst.substr(0, 8);
		auto dst2 = m_phyDst.substr(9, 8);

		m_texts["macDest"] = std::format("\tDestination: {}{} ({})", SDK::lookupMAC(dst1), dst2, m_phyDst);
	}

	return m_texts;
}

std::string Packet::formatBitSet(std::string bits) {
	// this regex just divides the bits to groups of four
	static std::regex r("(.{4})");
	// and then we put a space between them
	return std::regex_replace(bits, r, "$1 ");
}