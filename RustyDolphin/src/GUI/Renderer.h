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

// this class handles all of the rendering
// each `render` function renders a packet on the table (only the packet which need special treatment are implemented)
// each `renderExpanded` is specific for each type as it presents a lot more specific data
// renderExpanded also call the father class's renderExpanded
// for example, renderExpanded for tcp<IPV4> also calls renderExpanded for IPV4 which calls renderExpanded for Packet

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