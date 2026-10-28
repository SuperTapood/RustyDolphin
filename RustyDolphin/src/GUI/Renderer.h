#pragma once

#define IMGUI_USE_STB_SPRINTF

#include "GUI.h"

class Packet;
struct ApplicationState;
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
	explicit Renderer(ApplicationState& applicationState) : state(applicationState) {}
	void renderPacket(Packet* p);
	void renderDetails(Packet* p);
	bool filter(Packet* p);
	void filterPacket(Packet* p);
	void renderBase(Packet* p);
	void renderExpandedBase(Packet* p);
	void renderExpanded(ARP* p);
	void render(IPV4* p);
	void renderExpanded(IPV4* p);
	void renderExpanded(IGMP<IPV4>* p);
	void renderExpanded(IGMP<IPV6>* p);
	void renderExpanded(TCP<IPV4>* p);
	void renderExpanded(TCP<IPV6>* p);
	void renderExpanded(UDP<IPV4>* p);
	void renderExpanded(ICMP* p);
	void renderExpanded(UDP<IPV6>* p);
	void render(IPV6* p);
	void renderExpanded(IPV6* p);
	void renderExpanded(ICMPV6* p);

private:
	ApplicationState& state;
};
