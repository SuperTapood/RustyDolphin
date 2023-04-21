// todo: fix the igmp thing for some reason it's parsing the wrong values from the packet
//
#include <iostream>
#include <cstdio>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <winsock2.h>
#include <windows.h>
#include "Base/Base.h"
#include "Networks/Networks.h"
#include "Win/Win.h"
#include <cstdint>
//
///*
//b4 school:
//- able to select adapter (and show rate through the adapters)
//- captures saves and analyzes x packets to compare with wireshark
//- possibly test all other features? (Dearimgui, curl, winsdk, threading???)
//- check multiple apis to see which one works best!!! (Vulkan probs will, dx11 and dx9 are good bets (maybe metal for funsies?))
//
//[  ] Clean main
//[  ] change members to m_
//[  ] Make var names make sense
//[  ] use std memcpy instead of getting from the 
//[  ] Better types in packets
//[  ] winsdk free lol
//[  ] to strings should really be const
//[  ] each packet has two ui elements 1. Little summed up thing for the table view 2. Complex view for the little and big present windows
//[  ] switch to unique pointers for packets?
//[  ] Filtering:
//Each packet has a flag 1 passed filter 2 failed filter 0 unchecked. Second flag is somewhere else indicating a need to refilter. Upon refiltering, the string filter is converted to a a dict, which defaults of all options.
//[  ] For each packet:
//[  ] If there is no filter (""), render it.
//[  ] If there is a filter and the packrt flag is 0, check and mark it accordingly and render accordingly
//[  ] If the flag isn't 0 and filter flag isn't on, render according to flag,
//[  ] If filter flag is on, assume flag is 0 and filter it and mark it
//[  ] Mark filter flag as unchanged (off)
//
//The packer table:
//[  ] Button one under each other
//[  ] First n packets are rendered
//[  ] Can offset the n packets with scroll arrows
//[  ] Scroll bar is maybe dearimgui element?
//[  ] If not, button with changing size and position
//[  ] Size is percent of n from total (until threshold)
//[  ] Position is percent of offset from total
//[  ] Drag changes offset
//[  ] Pressing a button sets a variable to the packet's index (button idx + offset)
//[  ] Packet is presented according to that var
//[  ] Clicking again opens it in another window
//
//General flow:
//
//[  ] Init everything and caches
//[  ] Run sanity checks
//[  ] Fetch all adapters (maybe run some sort of check)
//[  ] Create render thread (maybe main?)
//[  ] Create a thread for each adapter to count packets and create rate
//[  ] Start rendering and present the rate
//[  ] Upon adapter selection, join threads and create another thread specifically for the chosen adapter
//[  ] Render the recieved packets which are picked up and analyzed by the thread
//[  ] Each packet is rendered according to the filrering
//[  ] On click, the packet will present in a small window
//[  ] On second one it will open in another window
//[  ] In both of these cases, buttons will be presented to do further actions (such as geo track)
//*/
//
///*
//* 
//There are many possible protocol values that can be used in a packet. Some common protocol values include:
//
//- ICMP (Internet Control Message Protocol): 1
//- TCP (Transmission Control Protocol): 6
//- UDP (User Datagram Protocol): 17
//- IGMP (Internet Group Management Protocol): 2
//- OSPF (Open Shortest Path First): 89
//- GRE (Generic Routing Encapsulation): 47
//- ESP (Encapsulating Security Payload): 50
//- AH (Authentication Header): 51
//
//These are just a few examples of the many possible protocol values that can be used in a packet. The protocol value tells the system how to treat the incoming packet.
//
//Is there anything else you would like to know?
//
//EtherType is a two-octet field in an Ethernet frame that is used to indicate which protocol is encapsulated in the payload of the frame. It is used at the receiving end by the data link layer to determine how the payload is processed. The same field is also used to indicate the size of some Ethernet frames².
//
//Some common EtherType values include:
//
//- IPv4: 0x0800
//- ARP: 0x0806
//- Wake-on-LAN: 0x0842
//- VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq: 0x8100
//- IPv6: 0x86DD
//- MPLS unicast: 0x8847
//- MPLS multicast: 0x8848
//
//These are just a few examples of the many possible EtherType values that can be used in an Ethernet frame.
//
//Is there anything else you would like to know?
//
//Source: Conversation with Bing, 04/04/2023(1) EtherType - Wikipedia. https://en.wikipedia.org/wiki/EtherType Accessed 04/04/2023.
//(2) Ether - Wikipedia. https://en.wikipedia.org/wiki/Ether Accessed 04/04/2023.
//(3) EtherType - NETWORX SECURITY. https://www.networxsecurity.org/members-area/glossary/e/ethertype.html Accessed 04/04/2023.
//
//To make rows clickable in Dear ImGui, you can use the Selectable widget. The Selectable widget takes a pointer to a function as its first argument. This function will be called when the row is clicked. The function can be used to perform any action you want, such as opening a new window or changing the value of a variable.
//
//For example, the following code will make the first row of a table clickable:
//
//bool clicked = false;
//ImGui::TableNextRow();
//ImGui::Selectable("Row 1", &clicked);
//The clicked variable will be set to true if the row is clicked. You can then use this variable to perform any action you want.
//
//Here is a more detailed example of how to make rows clickable in Dear ImGui:
//
//// Create a table
//ImGui::Begin("My Table");
//
//// Add a header row
//ImGui::TableSetupColumn("Name");
//ImGui::TableSetupColumn("Value");
//
//// Add some rows
//ImGui::TableNextRow();
//ImGui::TableSetColumnText("Name", "First Row");
//ImGui::TableSetColumnText("Value", "This is the first row.");
//
//ImGui::TableNextRow();
//ImGui::TableSetColumnText("Name", "Second Row");
//ImGui::TableSetColumnText("Value", "This is the second row.");
//
//// Make the first row clickable
//ImGui::Selectable("First Row", &clicked);
//
//// End the table
//ImGui::End();
//This code will create a table with two rows. The first row will be clickable, and the second row will not be clickable. When the first row is clicked, the clicked variable will be set to true.
// If you want the entire row to be selectable, you can modify the example code by adding the `ImGuiSelectableFlags_SpanAllColumns` flag to the `ImGui::Selectable` function. This will make the selectable widget span all columns and allow you to select the entire row by clicking anywhere on it. Here's an example:
//ImGui::Begin("Table with Selectable Rows");
//
//if (ImGui::BeginTable("table1", 3))
//{
//	ImGui::TableSetupColumn("Column 1");
//	ImGui::TableSetupColumn("Column 2");
//	ImGui::TableSetupColumn("Column 3");
//	ImGui::TableHeadersRow();
//
//	static bool selected[5] = { false, false, false, false, false };
//	for (int row = 0; row < 5; row++)
//	{
//		ImGui::TableNextRow();
//		for (int column = 0; column < 3; column++)
//		{
//			ImGui::TableSetColumnIndex(column);
//			if (column == 0)
//			{
//				char label[32];
//				sprintf(label, "Row %d", row);
//				if (ImGui::Selectable(label, &selected[row], ImGuiSelectableFlags_SpanAllColumns))
//				{
//					// do something when the row is selected
//				}
//			}
//			else
//			{
//				ImGui::Text("Cell %d,%d", row, column);
//			}
//		}
//	}
//
//	ImGui::EndTable();
//}
//
//ImGui::End();
//Is there anything else you would like to know ?
//*/
//
#define ETH_ALEN 6
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV6 0x86DD

void free() {
	Logger::free();
	Capture::free();
}

void init() {
	atexit(free);
	Logger::init();
	Capture::init();
	SDK::init();
}

void callback(pcap_pkthdr* header, const u_char* pkt_data) {
	u_int ip_len;
	u_short sport;

	struct ether_header* eth_header;
	eth_header = (struct ether_header*)pkt_data;
	long dport = -1, srport = -1;
	int type = 0;
	ip_header* ip_hdr = nullptr;

	auto p = fromRaw(header, pkt_data);

	// p->toString();

	std::cout << p->toString();
}

//int fmain() {
//	const long N = 500000;
//	u_char buffer[N];
//	std::fill(buffer, buffer + N, 0);
//
//	auto start = std::chrono::high_resolution_clock::now();
//	for (int i = 0; i < N; i++) {
//		buffer[i] = i;
//	}
//	auto end = std::chrono::high_resolution_clock::now();
//	auto a = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
//	std::cout << "Using buffer[index]: " << a << "ns" << std::endl;
//
//	start = std::chrono::high_resolution_clock::now();
//	std::memcpy(buffer, buffer, N);
//	end = std::chrono::high_resolution_clock::now();
//	auto b = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
//	std::cout << "Using std::memcpy(): " << b << "ns" << std::endl;
//
//	std::cout << "memcpy is " << ((float)a / (float)b) << " times faster";
//
//	return 0;
//}

//class MyClass {
//public:
//	long long_value;
//	int int_value1;
//	int int_value2;
//	short short_value;
//
//	MyClass(u_char* buffer, bool b) {
//		if (!b) {
//			return;
//		}
//		// Using buffer[index]
//		long long_value = buffer[0];
//		int int_value1 = buffer[4];
//		int int_value2 = buffer[8];
//		short short_value = buffer[12];
//
//		//// Using std::memcpy()
//		//std::memcpy(&long_value, buffer, sizeof(long));
//		//std::memcpy(&int_value1, buffer + sizeof(long), sizeof(int));
//		//std::memcpy(&int_value2, buffer + sizeof(long) + sizeof(int), sizeof(int));
//		//std::memcpy(&short_value, buffer + sizeof(long) + 2 * sizeof(int), sizeof(short));
//	}
//};

//int tmain() {
//	const int N = 1000000;
//	u_char buffer[N];
//	std::fill(buffer, buffer + N, 15);
//
//	auto start = std::chrono::high_resolution_clock::now();
//	for (int i = 0; i < N; i++) {
//		MyClass my_class(buffer, true);
//	}
//	auto end = std::chrono::high_resolution_clock::now();
//	std::cout << "Using buffer[index]: " << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() << "us" << std::endl;
//
//	start = std::chrono::high_resolution_clock::now();
//	for (int i = 0; i < N; i++) {
//		MyClass my_class(buffer, false);
//		std::memcpy(&my_class.long_value, buffer, sizeof(long));
//		std::memcpy(&my_class.int_value1, buffer + sizeof(long), sizeof(int));
//		std::memcpy(&my_class.int_value2, buffer + sizeof(long) + sizeof(int), sizeof(int));
//		std::memcpy(&my_class.short_value, buffer + sizeof(long) + 2 * sizeof(int), sizeof(short));
//	}
//	end = std::chrono::high_resolution_clock::now();
//	std::cout << "Using std::memcpy(): " << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() << "us" << std::endl;
//
//	return 0;
//}



int main()
{
	init();

	// SDK::printTables();
	
	Capture::loop(3, callback, true);

	return 0;
}