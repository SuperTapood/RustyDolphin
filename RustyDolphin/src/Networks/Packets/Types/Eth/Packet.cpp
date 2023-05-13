#include "Packet.h"
#include <iostream>
#include <sstream>
#include <memory>
#include <string>
#include <json.hpp>
#include <type_traits>
#include <pcap.h>
#include <iostream>
#include <sstream>
#include <ctime>
#include <WinSock2.h>

#include "../../../../Base/Base.h"

Packet::Packet(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx) {
	this->m_idx = idx;
	m_idxStr = std::to_string(idx);
	m_pktData = pkt_data;
	m_len = header->len;
	m_epoch = ((double)header->ts.tv_sec + (double)header->ts.tv_usec / 1000000.0);

	m_epoch -= Data::epochStart;

	m_phyDst = parseMAC();

	m_phySrc = parseMAC();

	m_type = parseShort();

	m_description = "base packet";

	m_expands.insert({ "Packet Title", false });
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

std::string Packet::parseMAC(unsigned int size) {
	std::stringstream ss;
	std::string mac;

	for (int i = pos + size; pos < i; pos++) {
		ss << std::setfill('0') << std::setw(2) << std::hex << (int)m_pktData[pos] << ":";
	}

	mac = ss.str();
	mac.pop_back();

	return mac;
}

std::string Packet::parseIPV4(unsigned int size) {
	std::stringstream ss;
	std::string ip;

	for (int i = pos + size; pos < i; pos++) {
		ss << (int)m_pktData[pos] << ".";
	}

	ip = ss.str();
	ip.pop_back();

	return ip;
}

std::string Packet::parseIPV6(unsigned int size) {
	std::stringstream ss;
	std::string ip;

	for (int i = pos + size; pos < i; pos += 2) {
		if ((int)m_pktData[pos] == 0 && (int)m_pktData[pos + 1] == 0) {
			ss << ":";
			continue;
		}
		ss << std::setfill('0') << std::setw(2) << std::hex << (int)m_pktData[pos] << std::setfill('0') << std::setw(2) << std::hex << (int)m_pktData[pos + 1] << ":";
	}

	ip = ss.str();
	ip.pop_back();

	return ip;
}

std::string Packet::parse(unsigned long long size) {
	std::string result;
	result.reserve(size * 2); // Each byte will be represented by 2 hexadecimal characters

	for (int end = pos + size; pos < end; pos++) {
		char buf[3];
		sprintf_s(buf, "%02x", (int)m_pktData[pos]);
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

	std::memcpy(&out, m_pktData + pos, len);

	pos += len;

	return htonll(out);
}

long Packet::parseLong() {
	long out;

	constexpr auto len = 4;

	std::memcpy(&out, m_pktData + pos, len);

	pos += len;

	return htonl(out);
}

int Packet::parseInt() {
	int out;

	constexpr auto len = 4;

	std::memcpy(&out, m_pktData + pos, len);

	pos += len;

	return htoni(out);
}

short Packet::parseShort() {
	short out;

	constexpr auto len = 2;

	std::memcpy(&out, m_pktData + pos, len);

	pos += len;

	return htons(out);
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

		m_texts["title"] = std::format("Frame {}: {} bytes on wire ({} bits)", m_idx, m_len, (m_len * 8));

		std::string result;
		result.reserve(m_len * 2); // Each byte will be represented by 2 hexadecimal characters

		for (int i = 0; i < m_len; i++) {
			char buf[3];
			sprintf_s(buf, "%02x", (int)m_pktData[i]);
			result.append(buf);
		}

		m_texts["hexData"] = result;
	}

	return m_texts;
}