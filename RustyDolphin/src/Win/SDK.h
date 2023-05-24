#pragma once

#include <map>
#include <string>
#include <WinSock2.h>
#include <iphlpapi.h>
#include <json.hpp>

using json = nlohmann::ordered_json;

class SDK {
public:
	static std::string ipAddress;
	// execute cmd in the, well, cmd (when the program is compiled it will open a cmd window for a moment)
	static std::string exec(const char* cmd);
	static void findIP(char* adName);
	static void init();
	static void release();
	static DWORD getPIDFromPort(DWORD port);
	static std::string getProcFromPID(DWORD PID);
	static std::string getProcFromPort(DWORD port);
	// geolocate the address
	static json geoLocate(std::string addr);
	// find the addresses a packet heading to addr might take
	static std::vector<std::string> traceRoute(std::string addr);
	// find location data for each of the hops to an address
	static void geoTrace(std::string addr);
	// used to prettify the mac address
	static std::string lookupMAC(std::string addr);

private:
	static std::map<DWORD, DWORD> PORT2PID;
	static std::map<DWORD, std::string> PID2PROC;

	// manif but in the memory
	static std::map<std::string, std::string> MACS;

	// used for the hopping map
	// but even the packets didn't hop as much as my sanity did when implementing this

	static HANDLE icmpHandle;
	static DWORD dwRetVal;
	static char* sendData;
	static LPVOID replyBuffer;
	static DWORD replySize;
	static IP_OPTION_INFORMATION ipOptions;

	static void initPIDCache();
	static void initICMP();
	static void refreshTables();
	static PMIB_TCPTABLE_OWNER_PID getTCPTable();
	static void refreshTCP();
	static PMIB_UDPTABLE_OWNER_PID getUDPTable();
	static void refreshUDP();
};