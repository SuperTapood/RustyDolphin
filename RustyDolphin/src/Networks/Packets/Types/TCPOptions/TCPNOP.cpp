#include "TCPNOP.h"

TCPNOP::TCPNOP() : TCPOption(1) {

}

std::string TCPNOP::toString() {
	return "No Operation";
}
