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
	static void filterPacket(Packet* p);
	static void render(Packet* p);
	static void renderExpanded(Packet* p);
	static void renderExpanded(ARP* p);
	static void render(IPV4* p);
	static void renderExpanded(IPV4* p);
	static void renderExpanded(IGMP<IPV4>* p);
	static void renderExpanded(IGMP<IPV6>* p);
	static void renderExpanded(TCP<IPV4>* p);
	static void renderExpanded(TCP<IPV6>* p);
	static void renderExpanded(UDP<IPV4>* p);
	static void renderExpanded(ICMP* p);
	static void renderExpanded(UDP<IPV6>* p);
	static void render(IPV6* p);
	static void renderExpanded(IPV6* p);
	static void renderExpanded(ICMPV6* p);

private:
	static bool filter(Packet* p);
};