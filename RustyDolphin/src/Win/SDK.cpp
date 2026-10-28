#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "SDK.h"

#include "../Base/Logger.h"
#include "../Base/ProtocolCatalog.h"
#include "../Base/ApplicationState.h"

#include <string>
#include <array>
#include <memory>
#include <Psapi.h>
#include <vector>
#include <tchar.h>
#include <iostream>
#include <memory>
#include <string.h>
#include <sstream>
#include <IcmpAPI.h>
#include <fstream>
#include <cstring>
#include <TlHelp32.h>
#include <stdexcept>
#include <WinHttp.h>

namespace {
std::string utf8(const wchar_t* value) {
	if (value == nullptr || value[0] == L'\0') return {};
	const int size = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
	if (size <= 1) return {};
	std::string result(static_cast<size_t>(size), '\0');
	WideCharToMultiByte(CP_UTF8, 0, value, -1, result.data(), size, nullptr, nullptr);
	result.pop_back();
	return result;
}

struct InternetHandleCloser {
	void operator()(HINTERNET handle) const noexcept { if (handle) WinHttpCloseHandle(handle); }
};
using InternetHandle = std::unique_ptr<void, InternetHandleCloser>;

std::wstring urlEncode(std::string_view value) {
	static constexpr wchar_t hex[] = L"0123456789ABCDEF";
	std::wstring encoded;
	for (const unsigned char byte : value) {
		if ((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
			(byte >= '0' && byte <= '9') || byte == '.' || byte == '-' || byte == '_' || byte == ':') {
			encoded.push_back(static_cast<wchar_t>(byte));
		}
		else {
			encoded += L'%';
			encoded += hex[byte >> 4];
			encoded += hex[byte & 0x0f];
		}
	}
	return encoded;
}

std::string httpGetGeo(std::string_view address, std::stop_token stopToken) {
	if (stopToken.stop_requested()) throw std::runtime_error("geolocation cancelled");
	InternetHandle session(WinHttpOpen(L"keycdn-tools:https://github.com/SuperTapood/RustyDolphin",
		WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
	if (!session) throw std::runtime_error("unable to initialize WinHTTP");
	WinHttpSetTimeouts(session.get(), 3000, 3000, 3000, 5000);
	InternetHandle connection(WinHttpConnect(session.get(), L"tools.keycdn.com", INTERNET_DEFAULT_HTTPS_PORT, 0));
	if (!connection) throw std::runtime_error("unable to connect to the geolocation service");
	const auto path = std::wstring(L"/geo.json?host=") + urlEncode(address);
	InternetHandle request(WinHttpOpenRequest(connection.get(), L"GET", path.c_str(), nullptr,
		WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
	if (!request || !WinHttpSendRequest(request.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0,
		WINHTTP_NO_REQUEST_DATA, 0, 0, 0) || !WinHttpReceiveResponse(request.get(), nullptr)) {
		throw std::runtime_error("geolocation request failed");
	}
	DWORD status = 0;
	DWORD statusSize = sizeof(status);
	if (!WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
		WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX) || status != 200) {
		throw std::runtime_error("geolocation service returned HTTP " + std::to_string(status));
	}
	std::string body;
	for (;;) {
		if (stopToken.stop_requested()) throw std::runtime_error("geolocation cancelled");
		DWORD available = 0;
		if (!WinHttpQueryDataAvailable(request.get(), &available)) throw std::runtime_error("unable to read geolocation response");
		if (available == 0) break;
		const auto oldSize = body.size();
		body.resize(oldSize + available);
		DWORD read = 0;
		if (!WinHttpReadData(request.get(), body.data() + oldSize, available, &read))
			throw std::runtime_error("unable to read geolocation response");
		body.resize(oldSize + read);
	}
	return body;
}
}

std::map<DWORD, DWORD> SDK::PORT2PID;
std::map<DWORD, std::string> SDK::PID2PROC;
HANDLE SDK::icmpHandle = INVALID_HANDLE_VALUE;
DWORD SDK::dwRetVal;
char* SDK::sendData = nullptr;
LPVOID SDK::replyBuffer = nullptr;
DWORD SDK::replySize;
IP_OPTION_INFORMATION SDK::ipOptions;
std::map<std::string, std::string> SDK::MACS;
std::string SDK::ipAddress;

std::optional<GeoLocation> SDK::geoLocate(const std::string& addr, std::stop_token stopToken) {
	auto res = httpGetGeo(addr, stopToken);
	const auto response = json::parse(res);
	if (response.value("status", "") != "success" || !response.contains("data") ||
		!response["data"].contains("geo")) {
		throw std::runtime_error(response.value("description", "geolocation service returned no data"));
	}

	const auto& geo = response["data"]["geo"];
	auto text = [&geo](const char* key, std::string fallback = "Unknown") {
		if (!geo.contains(key) || geo[key].is_null()) return fallback;
		if (geo[key].is_string()) return geo[key].get<std::string>();
		return geo[key].dump();
	};
	auto number = [&geo](const char* key) -> std::optional<double> {
		if (!geo.contains(key) || geo[key].is_null() || !geo[key].is_number()) return std::nullopt;
		return geo[key].get<double>();
	};

	return GeoLocation{
		.ip = text("ip", addr),
		.reverseDns = text("rdns"),
		.isp = text("isp"),
		.timezone = text("timezone"),
		.latitude = number("latitude"),
		.longitude = number("longitude")
	};
}

void SDK::initPIDCache() {
	PID2PROC.clear();
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		Logger::log("Unable to create a process snapshot");
		return;
	}

	PROCESSENTRY32 entry{};
	entry.dwSize = sizeof(entry);
	if (Process32First(snapshot, &entry)) {
		do {
			PID2PROC.insert_or_assign(entry.th32ProcessID, utf8(entry.szExeFile));
		} while (Process32Next(snapshot, &entry));
	}
	CloseHandle(snapshot);
}

PMIB_TCPTABLE_OWNER_PID SDK::getTCPTable() {
	DWORD dwSize = 0;
	PMIB_TCPTABLE_OWNER_PID tcpTable = nullptr;

	// get the needed size of the buffer
	if (GetExtendedTcpTable(nullptr, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) {
		std::cerr << "Failed to get required buffer size" << std::endl;
		return nullptr;
	}

	// allocate memory
	tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(dwSize);
	if (tcpTable == nullptr) {
		std::cerr << "Failed to allocate memory for TCP table" << std::endl;
		return nullptr;
	}

	// actually fetch the table
	if (GetExtendedTcpTable(tcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
		std::cerr << "Failed to get TCP table" << std::endl;
		free(tcpTable);
		return nullptr;
	}

	return tcpTable;
}

void SDK::refreshTCP() {
	auto table = SDK::getTCPTable();
	if (table == nullptr) {
		return;
	}

	for (DWORD i = 0; i < table->dwNumEntries; i++) {
		auto const& row = table->table[i];
		u_short port = ntohs((u_short)row.dwLocalPort);
		DWORD pid = row.dwOwningPid;
		PORT2PID.insert({ port, pid });
	}

	free(table);
}

PMIB_UDPTABLE_OWNER_PID SDK::getUDPTable() {
	DWORD dwSize = 0;
	PMIB_UDPTABLE_OWNER_PID udpTable = nullptr;

	// get the required buffer size
	if (GetExtendedUdpTable(nullptr, &dwSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER) {
		std::cerr << "Failed to get required buffer size" << std::endl;
		return nullptr;
	}

	// allocate memory
	udpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(dwSize);
	if (udpTable == NULL) {
		std::cerr << "Failed to allocate memory for TCP table" << std::endl;
		return nullptr;
	}

	// get the table
	if (GetExtendedUdpTable(udpTable, &dwSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
		std::cerr << "Failed to get UDP table" << std::endl;
		free(udpTable);
		return nullptr;
	}

	return udpTable;
}

void SDK::refreshUDP() {
	auto table = SDK::getUDPTable();
	if (table == nullptr) {
		return;
	}

	for (DWORD i = 0; i < table->dwNumEntries; i++) {
		auto& row = table->table[i];
		u_short port = ntohs((u_short)row.dwLocalPort);
		DWORD pid = row.dwOwningPid;
		PORT2PID.insert({ port, pid });
	}

	free(table);
}

void SDK::refreshTables() {
	PORT2PID.clear();
	refreshTCP();
	refreshUDP();
}

void SDK::findIP(char* adName) {
	ULONG buffer_size = sizeof(IP_ADAPTER_INFO);
	IP_ADAPTER_INFO* adapter_info = (IP_ADAPTER_INFO*)malloc(buffer_size);

	// get adapter info
	if (GetAdaptersInfo(adapter_info, &buffer_size) == ERROR_BUFFER_OVERFLOW) {
		free(adapter_info);
		adapter_info = (IP_ADAPTER_INFO*)malloc(buffer_size);
		GetAdaptersInfo(adapter_info, &buffer_size);
	}

	std::stringstream ss;

	std::string ad = adName;
	int i = 0;

	for (; i < ad.size(); i++) {
		if (ad.at(i) == '_') {
			i++;
			break;
		}
	}

	for (; i < ad.size(); i++) {
		ss << ad.at(i);
	}

	ad = ss.str();

	// find the right ip address
	for (IP_ADAPTER_INFO* adapter = adapter_info; adapter != nullptr; adapter = adapter->Next) {
		if ((adapter->AdapterName) == ad) {
			ipAddress = adapter->IpAddressList.IpAddress.String;
			break;
		}
	}

	free(adapter_info);
}

void SDK::initICMP() {
	dwRetVal = 0;
	std::string temp = "Data Buffer";
	sendData = new char[temp.size() + 1];
	std::ranges::copy(temp.begin(), temp.end(), sendData);
	sendData[temp.size()] = '\0';
	replyBuffer = nullptr;
	replySize = 0;
	ipOptions = { 0 };

	// create handle
	icmpHandle = IcmpCreateFile();
	if (icmpHandle == INVALID_HANDLE_VALUE) {
		printf("Unable to open ICMP handle\n");
		exit(1);
	}

	// set reply buffer size
	// IcmpSendEcho requires room for the reply header, request payload, and at
	// least eight additional bytes of ICMP error data.
	replySize = sizeof(ICMP_ECHO_REPLY) + static_cast<DWORD>(temp.size()) + 8;
	replyBuffer = malloc(replySize);
	if (replyBuffer == NULL) {
		printf("Unable to allocate memory for reply buffer\n");
		exit(1);
	}
}

void SDK::init() {
	initPIDCache();
	refreshTables();
	initICMP();

	// load the manuf file into memory
	std::ifstream manuf("deps/manuf/manuf");
	std::string line;

	while (getline(manuf, line)) {
		auto addr = line.substr(0, 8);
		auto firstTab = line.find("\t");
		auto secondTab = line.rfind("\t");
		auto name = line.substr(firstTab + 1, secondTab - firstTab - 1);

		MACS.try_emplace(addr, name);
	}

	MACS.try_emplace("33:33:00", "IPV6mcast");
}

void SDK::release() {
	if (replyBuffer != NULL) {
		free(replyBuffer);
	}
	delete[] sendData;
	sendData = nullptr;
	if (icmpHandle != INVALID_HANDLE_VALUE) {
		IcmpCloseHandle(icmpHandle);
		icmpHandle = INVALID_HANDLE_VALUE;
	}
}

DWORD SDK::getPIDFromPort(DWORD port) {
	if (PORT2PID.contains(port)) {
		return PORT2PID.at(port);
	}

	// if we can't find the port, refresh the tables
	refreshTables();

	if (PORT2PID.contains(port)) {
		return PORT2PID.at(port);
	}

	return MAXDWORD;
}

std::string SDK::getProcFromPID(DWORD PID) {
	if (PID == MAXDWORD) {
		// pid doesn't exist
		return "<UNKNOWN>";
	}

	if (PID2PROC.contains(PID)) {
		// we figured out this pid already
		return PID2PROC.at(PID);
	}

	TCHAR procName[MAX_PATH] = _T("4");
	HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, PID);

	if (proc == nullptr) {
		// couldn't open the process
		return "<BADPROCESS>";
	}

	if (!GetModuleBaseName(proc, nullptr, procName, _countof(procName))) {
		// process has not name
		CloseHandle(proc);
		return "<NAMELESS>";
	}

	std::string processName;

	// comvert TCHAR to std string :)
	processName = utf8(procName);

	// close the handle we opened
	CloseHandle(proc);

	// cache the results
	PID2PROC.try_emplace(PID, processName);

	return processName;
}

std::string SDK::getProcFromPort(DWORD port) {
	return getProcFromPID(getPIDFromPort(port));
}

std::vector<std::string> SDK::traceRoute(ApplicationState& state, const std::string& addr, std::stop_token stopToken) {
	unsigned long ipaddr = INADDR_NONE;
	// IP address string to binary
	ipaddr = inet_addr(addr.c_str());
	if (ipaddr == INADDR_NONE) {
		Logger::log("Unable to trace invalid IPv4 address: " + addr);
		return {};
	}

	u_char ttl = 1;
	std::vector<std::string> addrs;
	bool receivedRouteReply = false;

	while (ttl <= 30) {
		if (stopToken.stop_requested() || state.geoTerminate) {
			return addrs;
		}
		ipOptions.Ttl = ttl++;
		// send ICMP echo request
		dwRetVal = IcmpSendEcho(icmpHandle, ipaddr, sendData,
			static_cast<WORD>(std::strlen(sendData)),
			&ipOptions, replyBuffer, replySize, 150);
		if (dwRetVal != 0) {
			PICMP_ECHO_REPLY echoReply = (PICMP_ECHO_REPLY)replyBuffer;
			struct in_addr replyAddr;
			replyAddr.S_un.S_addr = echoReply->Address;
			const std::string replyAddress = inet_ntoa(replyAddr);
			receivedRouteReply = true;
			if (std::ranges::find(addrs, replyAddress) == addrs.end()) {
				addrs.emplace_back(replyAddress);
			}

			if (echoReply->Status == 0 || replyAddress == addr) {
				break;
			}
		}
	}

	if (stopToken.stop_requested() || state.geoTerminate) return addrs;
	if (std::ranges::find(addrs, addr) == addrs.end()) addrs.emplace_back(addr);
	if (!receivedRouteReply) {
		std::scoped_lock guard(state.geoGuard);
		state.geoError = "Intermediate routers blocked traceroute replies; showing the destination lookup.";
	}

	return addrs;
}

void SDK::geoTrace(std::stop_token stopToken, ApplicationState& state, std::string addr) {
	{
		std::scoped_lock guard(state.geoGuard);
		state.hopAddr = addr;
		state.geoError.clear();
		state.locs.clear();
	}
	state.geoDone = false;
	state.geoState = 1;
	auto vec = traceRoute(state, addr, stopToken);
	if (stopToken.stop_requested()) {
		state.geoDone = true;
		return;
	}
	state.geoState = 2;

	for (const auto& add : vec) {
		if (stopToken.stop_requested() || state.geoTerminate) {
			state.geoDone = true;
			return;
		}
		try {
			auto location = geoLocate(add, stopToken);
			if (location) {
				std::scoped_lock guard(state.geoGuard);
				state.locs.emplace_back(std::move(*location));
			}
		}
		catch (const std::exception& error) {
			Logger::log(std::string("Unable to geolocate ") + add + ": " + error.what());
			std::scoped_lock guard(state.geoGuard);
			state.geoError = error.what();
		}
	}

	bool locationsEmpty;
	{
		std::scoped_lock guard(state.geoGuard);
		locationsEmpty = state.locs.empty();
	}
	if (locationsEmpty) {
		state.geoState = 3;
	}
	else {
		state.geoState = 4;
	}
	state.geoDone = true;
}

std::string SDK::lookupMAC(std::string addr) {
	std::ranges::transform(addr.begin(), addr.end(), addr.begin(),
		[](unsigned char c) { return std::toupper(c); });

	if (MACS.contains(addr)) {
		return std::format("{}_", MACS.at(addr));
	}
	std::ranges::transform(addr.begin(), addr.end(), addr.begin(),
		[](unsigned char c) { return std::tolower(c); });

	return std::format("{}:", addr);
}
