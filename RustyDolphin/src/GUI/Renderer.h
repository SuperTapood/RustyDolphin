#pragma once

#include "GUI.h"

class Packet;
class ARP;
class IPV4;
class IPV6;
template <typename T>
class TCP;
template <typename T>
class UDP;



class Renderer {
public:
	static void render(Packet* p);
	static void render(ARP* p);
	static void render(TCP<IPV4>* p);
	static void render(TCP<IPV6>* p);
	static void render(UDP<IPV4>* p);
	static void render(UDP<IPV6>* p);
};