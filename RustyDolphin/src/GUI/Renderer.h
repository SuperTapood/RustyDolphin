#pragma once

#define IMGUI_USE_STB_SPRINTF

#include "GUI.h"

class Packet;
class ARP;
class IPV4;
class IPV6;
template <typename T>
class TCP;
template <typename T>
class UDP;
class ICMP;
class ICMPV6;
template <typename T>
class IGMP;

class Renderer {
public:
	static void render(Packet* p);
	static void renderExpanded(Packet* p);
	static void render(ARP* p);
	static void renderExpanded(ARP* p);
	static void render(IPV4* p);
	static void renderExpanded(IPV4* p);
	static void render(IGMP<IPV4>* p);
	static void renderExpanded(IGMP<IPV4>* p);
	static void render(TCP<IPV4>* p);
	static void renderExpanded(TCP<IPV4>* p);
	static void render(ICMP* p);
	static void render(UDP<IPV6>* p);
	static void render(IPV6* p);
	static void render(TCP<IPV6>* p);
	static void render(UDP<IPV4>* p);
	static void render(ICMPV6* p);
};