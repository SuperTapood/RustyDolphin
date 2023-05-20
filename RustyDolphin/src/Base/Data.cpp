#include "Data.h"
#include <iostream>

std::vector<Packet*> Data::captured;
int Data::selected = -1;
bool Data::doneCounting = false;
std::array<const char*, 30> Data::quotes = {
	"Less Cheese = More Cheese",
	"A man chooses, a slave obeys",
	"*sigh* i guess you are my little pugchamp",
	"compiled with <3",
	"where are my pants?",
	"Spain but the S is silent",
	"now with 5 percent more Bob Ross!",
	"I hardly know 'er!",
	"How you BEAN?",
	"You're breathtaking!",
	"The embodiment of page 2 of google search results",
	"Love is like frying food shirtless, you never know when it's going to hurt",
	"Water is just hydrogen soup",
	"Hey, got any grapes?",
	"'Hello there, old sport!' - an aubergine colored individual",
	"I don't get why circles exist. They're pointless.",
	"I'm afraid for the calendar. Its days are numbered.",
	"If the USA is so great why did they make a USB?",
	"Why are ducks always in a fowl mood?",
	"it is Wednesday my dudes",
	"Approved by official code bros",
	"'If it compiles, it's good; if it boots up, it's perfect.' - Linus Torvalds, Finnish Software Chad",
	"It Just Works.",
	"gotta love it when asynchronization works 60 percent out of 5 percent of the time",
	"The numbers Mason! What do they mean?!?!",
	"funny quote go brrrrr",
	"Built by a part time silly sandwich",
	"'Give someone state and they'll have a bug one day, but teach them how to represent state in two separate locations that have to be kept in sync and they'll have bugs for a lifetime.' - ryg",
	"The C++ giveth, and the C++ taketh away",
	"this quote has been left as an exercise for the reader"
};
long double Data::epochStart;
std::map<int, std::string> Data::dscpMap;
std::map<int, std::string> Data::ecnMap;
std::map<int, std::string> Data::hopMap;
std::map<unsigned char, std::string> Data::icmpv6Types;
bool Data::doneCapturing = false;
long Data::capIdx = 0;
bool Data::showStop = false;
bool Data::showStart = false;
bool Data::doneLoading = false;
bool Data::showSave = false;
bool Data::showLoad = false;
std::thread Data::captureThread;
pcap_t* Data::chosenAdapter;
std::mutex Data::guard;
bool Data::fileAdapter;
std::array<const char*, 10> Data::TCPFlags = {
	"RES", "ACN", "CWR", "ECE", "URG", "ACK", "PSH", "RST", "SYN", "FIN"
};

char Data::filterTxt[1024];
std::set<std::string> Data::filterKeys = {
	"ip", "sport", "dport", "saddr", "daddr", "proto", "num", "len", "proc"
};
std::map<std::string, std::string> Data::filter;
std::string Data::filterIssue;
bool Data::showBadFilter;
bool Data::newFilter = true;

void Data::init() {
	dscpMap[0] = "Default";
	dscpMap[10] = "AF11";
	dscpMap[12] = "AF12";
	dscpMap[14] = "AF13";
	dscpMap[18] = "AF21";
	dscpMap[20] = "AF22";
	dscpMap[22] = "AF23";
	dscpMap[26] = "AF31";
	dscpMap[28] = "AF32";
	dscpMap[30] = "AF33";
	dscpMap[34] = "AF41";
	dscpMap[36] = "AF42";
	dscpMap[38] = "AF43";
	dscpMap[8] = "CS1";
	dscpMap[16] = "CS2";
	dscpMap[24] = "CS3";
	dscpMap[32] = "CS4";
	dscpMap[40] = "CS5";
	dscpMap[48] = "CS6";
	dscpMap[56] = "CS7";
	dscpMap[46] = "EF";

	ecnMap[0] = "Not-ECT";
	ecnMap[1] = "ECT(1)";
	ecnMap[2] = "ECT(0)";
	ecnMap[3] = "CE";

	hopMap[0x00] = "Pad1";
	hopMap[0x01] = "PadN";
	hopMap[0xC2] = "Jumbo Payload";
	hopMap[0x23] = "Tunnel Encapsulation Limit";
	hopMap[0x63] = "Tunnel Encapsulation Limit";
	hopMap[0x04] = "Tunnel Encapsulation Limit";
	hopMap[0x05] = "Router Alert";
	hopMap[0x26] = "Quick-Start";
	hopMap[0x07] = "CALIPSO";
	hopMap[0x08] = "Home Address";
	hopMap[0xC9] = "Home Address";
	hopMap[0x8A] = "ILNP Nonce";
	hopMap[0x8B] = "ILNP Nonce";
	hopMap[0x8C] = "Deprecated";
	hopMap[0x4D] = "Deprecated";
	hopMap[0x6D] = "MPL Option";
	hopMap[0xEE] = "Performance and Diagnostic Metrics (PDM)";
	hopMap[0x0F] = "Performance and Diagnostic Metrics (PDM)";
	hopMap[0x30] = "Minimum Path MTU Hop-by-Hop Option";
	hopMap[0x12] = "AltMark";

	icmpv6Types[1] = "Destination Unreachable";
	icmpv6Types[2] = "Packet Too Big";
	icmpv6Types[3] = "Time Exceeded";
	icmpv6Types[4] = "Parameter Problem";
	icmpv6Types[127] = "Reserved for expansion of ICMPv6 error messages";
	icmpv6Types[128] = "Echo Request";
	icmpv6Types[129] = "Echo Reply";
	icmpv6Types[130] = "Multicast Listener Query";
	icmpv6Types[131] = "Multicast Listener Report";
	icmpv6Types[132] = "Multicast Listener Done";
	icmpv6Types[133] = "Router Solicitation";
	icmpv6Types[134] = "Router Advertisement";
	icmpv6Types[135] = "Neighbor Solicitation";
	icmpv6Types[136] = "Neighbor Advertisement";
	icmpv6Types[137] = "Redirect Message";
	icmpv6Types[138] = "Router Renumbering";
	icmpv6Types[139] = "ICMP Node Information Query";
	icmpv6Types[140] = "ICMP Node Information Response";
	icmpv6Types[141] = "Inverse Neighbor Discovery Solicitation Message";
	icmpv6Types[142] = "Inverse Neighbor Discovery Advertisement Message";
	icmpv6Types[143] = "Version 2 Multicast Listener Report";
	icmpv6Types[144] = "Home Agent Address Discovery Request Message";
	icmpv6Types[145] = "Home Agent Address Discovery Reply Message";
	icmpv6Types[146] = "Mobile Prefix Solicitation";
	icmpv6Types[147] = "Mobile Prefix Advertisement";
	icmpv6Types[148] = "Certification Path Solicitation Message";
	icmpv6Types[149] = "Certification Path Advertisement Message";
	icmpv6Types[150] = "ICMP messages utilized by experimental mobility protocols such as Seamoby";
	icmpv6Types[151] = "Multicast Router Advertisement";
	icmpv6Types[152] = "Multicast Router Solicitation";
	icmpv6Types[153] = "Multicast Router Termination";
	icmpv6Types[154] = "FMIPv6 Messages";
	icmpv6Types[155] = "RPL Control Message";
	icmpv6Types[156] = "ILNPv6 Locator Update Message";
	icmpv6Types[157] = "Duplicate Address Request";
	icmpv6Types[158] = "Duplicate Address Confirmation";
	icmpv6Types[159] = "MPL Control Message";
	icmpv6Types[160] = "Extended Echo Request";
	icmpv6Types[161] = "Extended Echo Reply";
}

void Data::addPacket(Packet* p) {
	captured.push_back(p);
}

void Data::processFilter() {
	filter["ip"] = "";
	filter["sport"] = "";
	filter["dport"] = "";
	filter["saddr"] = "";
	filter["daddr"] = "";
	filter["proto"] = "";
	filter["num"] = "";
	filter["len"] = "";
	filter["proc"] = "";
	Data::newFilter = true;
	
	// filter is empty
	if (Data::filterTxt[0] == '\0') {
		return;
	}
	std::vector<std::string> args;
	std::stringstream ss(filterTxt);
	std::string current;
	std::size_t first, last;

	while (std::getline(ss, current, ',')) {
		auto eq = current.find_first_of('=');
		if (eq != current.find_last_of('=')) {
			showBadFilter = true;
			filterIssue = std::format("{} is not a valid filter", current);
			filter["num"] = "-1";
			return;
		}
		auto key = current.substr(0, eq);
		first = key.find_first_not_of(' ');
		last = key.find_last_not_of(' ');
		key = key.substr(first, last - first + 1);

		auto value = current.substr(eq + 1);
		first = value.find_first_not_of(' ');
		last = value.find_last_not_of(' ');
		value = value.substr(first, last - first + 1);

		args.push_back(key);
		args.push_back(value);
	}

	if (args.size() % 2 == 1) {
		showBadFilter = true;
		filterIssue = "the number of arguments isn't even.";
		filter["num"] = "-1";
		return;
	}

	for (int idx = 0; idx < args.size(); idx += 2) {
		auto key = args.at(idx);
		auto value = args.at(idx + 1);
		//std::cout << key << " - " << value << std::endl;

		if (!filterKeys.contains(key)) {
			showBadFilter = true;
			filterIssue = std::format("'{}' isn't a valid filter flag.", key);
			filter["num"] = "-1";
			return;
		}

		filter[key] = value;
	}

	/*for (auto key : filter) {
		std::cout << key.first << ":" << key.second << std::endl;
	}*/
}