#include "Data.h"

std::vector<Packet*> Data::captured;
int Data::selected = -1;
bool Data::doneCounting = false;
std::array<const char*, 30> Data::quotes = {
	"Less Cheese = More Cheese",
	"A man chooses, a slave obeys",
	"*sigh* i guess you are my little pugchamp",
	"made with <3",
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
	"Panem et Circenses",
	"this quote has been left as an exercise for the reader"
};
long double Data::epochStart;
std::map<int, std::string> Data::dscpMap;
std::map<int, std::string> Data::ecnMap;
bool Data::doneCapturing = false;
long Data::capIdx = 0;
bool Data::showStop = false;
bool Data::showStart = false;
std::thread Data::captureThread;
pcap_t* Data::chosenAdapter;
std::mutex Data::guard;
bool Data::fileAdapter;

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
}

void Data::addPacket(Packet* p) {
	captured.push_back(p);
}