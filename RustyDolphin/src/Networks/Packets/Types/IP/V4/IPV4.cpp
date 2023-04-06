#include "IPV4.h"

#include <sstream>
#include <vector>
#include "../../../../../Base/Logger.h"
#include "../../../../Capture.h"

IPV4::IPV4(pcap_pkthdr* header, const u_char* pkt_data) : Packet(header, pkt_data) {
	headerLength = (int)pkt_data[pos++] & 0x0F;
	differServ = (int)pkt_data[pos++];

	totalLength = (int)parseLong(&pos, pos + 2);

	identification = (int)parseLong(&pos, pos + 2);

	flags = pkt_data[pos++];

	fragmentationOffset = pkt_data[pos++];

	ttl = pkt_data[pos++];

	proto = pkt_data[pos++];

	headerChecksum = (int)parseLong(&pos, pos + 2);

	// proto size is 4 :)
	srcAddr = parseIPV4(&pos, pos + 4);

	destAddr = parseIPV4(&pos, pos + 4);

	int diff = headerLength - 20;
	IPoptionsCount = 0;
	std::vector<IPV4Option> vec;

	while (diff > 0) {
		IPoptionsCount++;

		int code = pkt_data[pos] & 0x00011111;

		constexpr auto routerAlert = 20;

		switch (code) {
		case routerAlert:
			vec.push_back(RouterAlert(header, pkt_data, &pos));
			break;
		default:
			Logger::log("bad ip option of packet data");
			Capture::dump(header, pkt_data);
			break;
		}
	}

	if (diff > 0) {
		opts = (IPV4Option*)malloc(sizeof(IPV4Option) * IPoptionsCount);

		std::copy(vec.begin(), vec.end(), opts);
	}
}

std::string IPV4::toString() {
	std::stringstream ss;

	ss << "IPV4 Packet at " << m_time << " of length " << totalLength << " from " << srcAddr << " to " << destAddr << " transfer protocol is " << proto << " with options: ";

	for (int i = 0; i < IPoptionsCount; i++) {
		ss << opts[i].toString() << ", ";
	}

	return ss.str();
}