#include "ICMPV6Type.h"

#include "../../../Eth/Packet.h"

#include "../../../../../../Base/Data.h"

ICMPV6Type::ICMPV6Type(Packet* packet) {
	m_type = packet->parseChar();
	m_code = packet->parseChar();

	
	m_typeStr = Data::icmpv6Types[m_type];

	switch ((int)m_type) {
	case 1:
		m_codeStr = resolveDestUnreach(m_code);
		break;
	case 3:
		m_codeStr = resolveTimeExceeded(m_code);
		break;
	case 4:
		m_codeStr = resolveParameterProblem(m_code);
		break;
	case 138:
		m_codeStr = resolveRouterRenumbering(m_code);
		break;
	case 139:
		m_codeStr = resolveNodeQuery(m_code);
		break;
	case 140:
		m_codeStr = resolveNodeInfo(m_code);
		break;
	case 157:
		m_codeStr = resolveDupeAddrReq(m_code);
		break;
	case 158:
		m_codeStr = resolveDupeAddrCon(m_code);
		break;
	case 160:
		m_codeStr = resolveExtendedEchoReq(m_code);
		break;
	case 161:
		m_codeStr = resolveExtendedEchoRep(m_code);
		break;
	default:
		m_codeStr = std::to_string(m_code);
		break;
	}
}

std::string ICMPV6Type::resolveDestUnreach(unsigned char code) {
	switch ((int)code) {
	case 0:
		return "no route to destination";
	case 1:
		return "communication with destination administratively prohibited";
	case 2:
		return "beyond scope of source address";
	case 3:
		return "address unreachable";
	case 4:
		return "port unreachable";
	case 5:
		return "source address failed ingress/egress policy";
	case 6:
		return "reject route to destination";
	case 7:
		return "Error in Source Routing Header";
	case 8:
		return "Headers too long";
	}
}

std::string ICMPV6Type::resolveTimeExceeded(unsigned char code) {
	if ((int)code == 0) {
		return "hop limit exceeded in transit";
	}

	return "fragment reassembly time exceeded";
}

std::string ICMPV6Type::resolveParameterProblem(unsigned char code) {
	switch ((int)code) {
	case 0:
		return "erroneous header field encountered";
	case 1:
		return "unrecognized Next Header type encountered";
	case 2:
		return "unrecognized IPv6 option encountered";
	case 3:
		return "IPv6 First Fragment has incomplete IPv6 Header Chain";
	case 4:
		return "SR Upper-layer Header Error";
	case 5:
		return "Unrecognized Next Header type encountered by intermediate node";
	case 6:
		return "Extension header too big";
	case 7:
		return "Extension header chain too long";
	case 8:
		return "Too many extension headers";
	case 9:
		return "Too many options in extension header";
	case 10:
		return "Option too big";
	}
}

std::string ICMPV6Type::resolveRouterRenumbering(unsigned char code) {
	switch ((int)code) {
	case 0:
		return "Router Renumbering Command";
	case 1:
		return "Router Renumbering Result";
	case 255:
		return "Sequence Number Reset";
	}
}

std::string ICMPV6Type::resolveNodeQuery(unsigned char code) {
	switch ((int)code) {
	case 0:
		return "The Data field contains an IPv6 address which is the Subject of this Query.";
	case 1:
		return "The Data field contains a name which is the Subject of this Query, or is empty, as in the case of a NOOP.";
	case 2:
		return "The Data field contains an IPv4 address which is the Subject of this Query.";
	}
}

std::string ICMPV6Type::resolveNodeInfo(unsigned char code) {
	switch ((int)code) {
	case 0:
		return "A successful reply. The Reply Data field may or may not be empty.";
	case 1:
		return "The Responder refuses to supply the answer. The Reply Data field will be empty.";
	case 2:
		return "The Qtype of the Query is unknown to the Responder. The Reply Data field will be empty.";
	}
}

std::string ICMPV6Type::resolveDupeAddrReq(unsigned char code) {
	if ((int)code == 0) {
		return "DAR message";
	}

	return std::format("EDAR message with {}-bit ROVR field", 64 * (int)code);
}

std::string ICMPV6Type::resolveDupeAddrCon(unsigned char code) {
	if ((int)code == 0) {
		return "DAC message";
	}

	return std::format("EDAC message with {}-bit ROVR field", 64 * (int)code);
}

std::string ICMPV6Type::resolveExtendedEchoReq(unsigned char code) {
	return "No Error";
}

std::string ICMPV6Type::resolveExtendedEchoRep(unsigned char code) {
	switch ((int)code) {
	case 0:
		return "No Error";
	case 1:
		return "Malformed Query";
	case 2:
		return "No Such Interface";
	case 3:
		return "No Such Table Entry";
	case 4:
		return "Multiple Interfaces Satisfy Query";
	}
}
