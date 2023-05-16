#pragma once

#include <string>

class Packet;

class ICMPV6Type {
public:
	unsigned char m_type;
	unsigned char m_code;

	std::string m_typeStr;
	std::string m_codeStr;

	ICMPV6Type(Packet* packet);

private:

	std::string resolveDestUnreach(unsigned char code);
	std::string resolveTimeExceeded(unsigned char code);
	std::string resolveParameterProblem(unsigned char code);
	std::string resolveRouterRenumbering(unsigned char code);
	std::string resolveNodeQuery(unsigned char code);
	std::string resolveNodeInfo(unsigned char code);
	std::string resolveDupeAddrReq(unsigned char code);
	std::string resolveDupeAddrCon(unsigned char code);
	std::string resolveExtendedEchoReq(unsigned char code);
	std::string resolveExtendedEchoRep(unsigned char code);
};