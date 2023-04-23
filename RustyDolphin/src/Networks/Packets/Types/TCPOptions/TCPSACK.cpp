#include "TCPSACK.h"

TCPSACK::TCPSACK(pcap_pkthdr* header, const u_char* pkt_data, int* pos) : TCPOption(5) {
	len = pkt_data[(*pos)++];

	edges = (len - 2) / 8;

	Ledges = new long long[edges];
	Redges = new long long[edges];

	for (int i = 0; i < edges; i++) {
		Ledges[i] = parseLong(pos, (*pos) + 4, pkt_data);
		Redges[i] = parseLong(pos, (*pos) + 4, pkt_data);
	}
}

std::string TCPSACK::toString() {
	std::stringstream ss;

	ss << "TCP Option SACK of " << edges << " edges (";

	for (int i = 0; i < edges; i++) {
		ss << " from " << Ledges[i] << " to " << Redges[i] << ",";
	}

	ss << ")";

	return ss.str();
}