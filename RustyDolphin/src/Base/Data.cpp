#include "Data.h"

std::vector<Packet*> Data::captured;
int Data::selected = -1;


void Data::addPacket(Packet* p) {
	captured.push_back(p);
}