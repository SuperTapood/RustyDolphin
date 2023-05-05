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

#include "../../../../GUI/Renderer.h"

Packet::Packet(pcap_pkthdr* header, const u_char* pkt_data, unsigned int idx) {
	this->idx = idx;
	this->m_pktData = pkt_data;
	struct tm timeinfo;
	m_epoch = header->ts.tv_sec;
	localtime_s(&timeinfo, &m_epoch);
	std::stringstream ss;
	int year = 1900 + timeinfo.tm_year;
	int month = 1 + timeinfo.tm_mon;

	ss << year << "/" << padDate(month) << "/" << padDate(timeinfo.tm_mday) << " " << padDate(timeinfo.tm_hour) << ":" << padDate(timeinfo.tm_min) << ":" << padDate(timeinfo.tm_sec);

	pos = 0;
	m_time = ss.str();

	m_phyDst = parseMAC();

	m_phySrc = parseMAC();

	m_len = header->len;

	m_type = parseShort();
}

std::string Packet::toString() {
	std::stringstream ss;

	ss << "Base Packet at " << m_time << " of len " << m_len << " type: " << m_type << " from " << m_phySrc << " to " << m_phyDst << "\n";

	return ss.str();
}

json Packet::jsonify() {
	json j = {
		{"header", "start"},
		{"time", m_time},
		{"epoch", m_epoch},
		{"len", m_len},
		{"base packet", "start"},
		{"physical destination", m_phyDst},
		{"physical source", m_phySrc},
		{"packet type", m_type},
	};

	return j;
}

void Packet::render() {
	Renderer::render(this);
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
		ss << std::setfill('0') << std::setw(2) << std::hex << (int)m_pktData[pos] << std::hex << (int)m_pktData[pos + 1] << ":";
	}

	ip = ss.str();
	ip.pop_back();

	return ip;
}

std::string Packet::parse(unsigned long long size) {
	std::stringstream ss;

	for (int end = pos + size; pos < end; pos++) {
		ss << std::hex << (int)m_pktData[pos];
	}

	return ss.str();
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