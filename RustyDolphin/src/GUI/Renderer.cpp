#include "Renderer.h"

#include "../Base/Data.h"
#include "../Networks/Packets/Types/Types.h"

bool Renderer::filter(Packet* p) {
	if (!Data::newFilter) {
		if (p->m_flag == FilterFlag::Passed) {
			return true;
		}
		else if (p->m_flag == FilterFlag::Failed) {
			return false;
		}
	}

	for (auto pair : Data::filter) {
		if (pair.second == "") {
			continue;
		}

		if (!p->m_properties.contains(pair.first)) {
			p->m_flag = FilterFlag::Failed;
			return false;
		}

		if (p->m_properties.at(pair.first) != pair.second) {
			p->m_flag = FilterFlag::Failed;
			return false;
		}
	}

	p->m_flag = FilterFlag::Passed;
	return true;
}

void Renderer::filterPacket(Packet* p) {
	if (filter(p)) {
		Data::displayed++;
		ImGui::TableNextRow();
		p->render();
	}
}

void Renderer::render(Packet* p) {
	ImGui::TableSetColumnIndex(0);
	if (ImGui::Selectable(p->m_idxStr.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
		Data::selected = p->m_idx;
	}
	ImGui::TableSetColumnIndex(1);
	ImGui::Text("%f", p->m_epoch - Data::epochStart);
	ImGui::TableSetColumnIndex(2);
	ImGui::Text(p->m_phySrc.c_str());
	ImGui::TableSetColumnIndex(3);
	ImGui::Text(p->m_phyDst.c_str());
	ImGui::TableSetColumnIndex(4);
	ImGui::Text(p->m_strType.c_str());
	ImGui::TableSetColumnIndex(5);
	ImGui::Text("%d", p->m_len);
	ImGui::TableSetColumnIndex(6);
	ImGui::Text(p->m_description.c_str());
}

void Renderer::renderExpanded(Packet* p) {
	auto map = p->getTexts();
	if (ImGui::Button(map.at("title").c_str())) {
		p->m_expands.at("Packet Title") = !p->m_expands.at("Packet Title");
	}

	if (p->m_expands.at("Packet Title")) {
		ImGui::Text(("\tArrival time: " + map.at("time")).c_str());
		ImGui::Text(map.at("macDest").c_str());
		ImGui::Text(map.at("macSrc").c_str());
		ImGui::Text(("\tType: " + p->m_strType).c_str());
	}
}

void Renderer::renderExpanded(ARP* p) {
	renderExpanded((Packet*)p);

	auto map = p->getTexts();

	if (ImGui::Button(map.at("arpTitle").c_str())) {
		p->m_expands.at("ARP Title") = !p->m_expands.at("ARP Title");
	}

	if (p->m_expands.at("ARP Title")) {
		ImGui::Text(("\tHardware type: " + map.at("hardType")).c_str());
		ImGui::Text(("\tProtocol type: " + map.at("protoType")).c_str());
		ImGui::Text(("\tHardware size: " + std::to_string(p->m_hardSize)).c_str());
		ImGui::Text(("\tProtocol size: " + std::to_string(p->m_protoSize)).c_str());
		ImGui::Text(("\tOpcode: " + map.at("opcode")).c_str());
		ImGui::Text(("\tSender MAC Address: " + p->m_sendMAC).c_str());
		ImGui::Text(("\tSender IP Address: " + p->m_sendAddr).c_str());
		ImGui::Text(("\tTarget MAC Address: " + p->m_targetMAC).c_str());
		ImGui::Text(("\tTarget IP Address: " + p->m_targetAddr).c_str());
	}
}

void Renderer::render(IPV4* p) {
	ImGui::TableSetColumnIndex(0);
	if (ImGui::Selectable(p->m_idxStr.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
		Data::selected = p->m_idx;
	}
	ImGui::TableSetColumnIndex(1);
	ImGui::Text("%f", p->m_epoch - Data::epochStart);
	ImGui::TableSetColumnIndex(2);
	ImGui::Text(p->m_srcAddr.c_str());
	ImGui::TableSetColumnIndex(3);
	ImGui::Text(p->m_destAddr.c_str());
	ImGui::TableSetColumnIndex(4);
	ImGui::Text(p->m_strType.c_str());
	ImGui::TableSetColumnIndex(5);
	ImGui::Text("%d", p->m_len);
	ImGui::TableSetColumnIndex(6);
	ImGui::Text(p->m_description.c_str());
}

void Renderer::renderExpanded(IPV4* p) {
	renderExpanded((Packet*)p);

	auto m = p->getTexts();

	if (ImGui::Button(m.at("IPTitle").c_str())) {
		p->m_expands.at("IPV4 Title") = !p->m_expands.at("IPV4 Title");
	}

	if (p->m_expands.at("IPV4 Title")) {
		ImGui::Text("\t0100 . . . . = Version 4");
		ImGui::Text(m.at("headerLen").c_str());
		if (ImGui::Button(m.at("differServ").c_str())) {
			p->m_expands.at("DifferServ") = !p->m_expands.at("DifferServ");
		}

		if (p->m_expands.at("DifferServ")) {
			ImGui::Text(m.at("DSCP").c_str());
			ImGui::Text(m.at("ECN").c_str());
		}

		ImGui::Text("\tTotal Length: %d", p->m_totalLength);
		ImGui::Text(m.at("ID").c_str());
		if (ImGui::Button(m.at("IPFlags").c_str())) {
			p->m_expands.at("Flags") = !p->m_expands.at("Flags");
		}

		if (p->m_expands.at("Flags")) {
			ImGui::Text(m.at("resBits").c_str());
			ImGui::Text(m.at("dfBits").c_str());
			ImGui::Text(m.at("mfBits").c_str());
		}

		ImGui::Text(m.at("offset").c_str());
		ImGui::Text("\tTime to Live: %d", p->m_ttl);
		ImGui::Text(m.at("proto").c_str());
		ImGui::Text(m.at("IPChecksum").c_str());
		ImGui::Text(m.at("src").c_str());
		ImGui::Text(m.at("dest").c_str());

		if (p->m_IPoptionsCount > 0) {
			if (ImGui::Button(m.at("optStr").c_str())) {
				p->m_expands.at("Options General") = !p->m_expands.at("Options General");
			}

			if (p->m_expands.at("Options General")) {
				for (int i = 0; i < p->m_ipOptTexts.size(); i++) {
					auto b = p->m_ipOptTexts.at(i);
					if (ImGui::Button(b.c_str())) {
						p->m_expands.at(std::format("option %d", i)) = !p->m_expands.at(std::format("option %d", i));
					}

					if (p->m_expands.at(std::format("option %d", i))) {
						for (auto t : p->m_opts.at(i)->data) {
							ImGui::Text(t.c_str());
						}
					}
				}
			}
		}
		
		if (ImGui::Button("   Geo Trace this Packet? (will open a pop up with the info)")) {
			Data::showGeoTrace = p->m_idx;
			Data::geoLocThread = std::jthread(SDK::geoTrace, p->getAlienAddr());
		}
	}
}

void Renderer::render(IPV6* p) {
	ImGui::TableSetColumnIndex(0);
	if (ImGui::Selectable(p->m_idxStr.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
		Data::selected = p->m_idx;
	}
	ImGui::TableSetColumnIndex(1);
	ImGui::Text("%f", p->m_epoch - Data::epochStart);
	ImGui::TableSetColumnIndex(2);
	ImGui::Text(p->m_srcAddr.c_str());
	ImGui::TableSetColumnIndex(3);
	ImGui::Text(p->m_destAddr.c_str());
	ImGui::TableSetColumnIndex(4);
	ImGui::Text(p->m_strType.c_str());
	ImGui::TableSetColumnIndex(5);
	ImGui::Text("%d", p->m_len);
	ImGui::TableSetColumnIndex(6);
	ImGui::Text(p->m_description.c_str());
}

void Renderer::renderExpanded(IPV6* p) {
	renderExpanded((Packet*)p);
	auto m = p->getTexts();
	if (ImGui::Button(m.at("IPV6 Title").c_str())) {
		p->m_expands["IPV6 Title"] = !p->m_expands["IPV6 Title"];
	}

	if (p->m_expands["IPV6 Title"]) {
		ImGui::Text("\t0110  . . . . = Version: 6");
		if (ImGui::Button(m.at("Traffic Class").c_str())) {
			p->m_expands["Traffic Class"] = !p->m_expands["Traffic Class"];
		}

		if (p->m_expands["Traffic Class"]) {
			ImGui::Text(m.at("DSCP").c_str());
			ImGui::Text(m.at("ECN").c_str());
		}
		ImGui::Text(m.at("Flow Label").c_str());
		ImGui::Text(m.at("Payload Length").c_str());
		ImGui::Text(m.at("Next Header").c_str());
		ImGui::Text(m.at("Hop Limit").c_str());
		ImGui::Text(m.at("IPV6 Source").c_str());
		ImGui::Text(m.at("IPV6 Destination").c_str());

		if (p->m_options.size() > 0) {
			if (ImGui::Button(m.at("IPV6 Option Title").c_str())) {
				p->m_expands["IPV6 Option Title"] = !p->m_expands["IPV6 Option Title"];
			}

			if (p->m_expands["IPV6 Option Title"]) {
				ImGui::Text(m.at("IPV6 Option Next Header").c_str());
				ImGui::Text(m.at("IPV6 Option Length").c_str());

				for (auto b : p->m_ipOptTexts) {
					ImGui::Text(b.c_str());
				}
			}
		}
	}
}

void Renderer::renderExpanded(TCP<IPV4>* p) {
	renderExpanded((IPV4*)p);

	auto m = p->getTexts();

	if (ImGui::Button(m.at("TCP Title").c_str())) {
		p->m_expands.at("TCP Title") = !p->m_expands.at("TCP Title");
	}

	if (p->m_expands.at("TCP Title")) {
		ImGui::Text(m.at("SPort").c_str());
		ImGui::Text(m.at("DPort").c_str());
		ImGui::Text(m.at("SeqNum").c_str());
		ImGui::Text(m.at("AckNum").c_str());
		ImGui::Text(m.at("HeaderLen").c_str());

		if (ImGui::Button(m.at("TCPFlags").c_str())) {
			p->m_expands.at("TCP Flags") = !p->m_expands.at("TCP Flags");
		}

		if (p->m_expands.at("TCP Flags")) {
			for (auto s : Data::TCPFlags) {
				ImGui::Text(m.at(s).c_str());
			}
		}
		ImGui::Text(m.at("TCPWindow").c_str());
		ImGui::Text(m.at("TCPChecksum").c_str());
		ImGui::Text(m.at("UrgentPtr").c_str());

		if (ImGui::Button(m.at("OptionTitle").c_str())) {
			p->m_expands["TCP Options"] = !p->m_expands["TCP Options"];
		}

		if (p->m_expands["TCP Options"]) {
			for (auto opt : p->m_options) {
				ImGui::Text(("\t\t" + opt->toString()).c_str());
			}
		}
	}
}

void Renderer::renderExpanded(TCP<IPV6>* p) {
	renderExpanded((IPV6*)p);

	auto m = p->getTexts();

	if (ImGui::Button(m.at("TCP Title").c_str())) {
		p->m_expands.at("TCP Title") = !p->m_expands.at("TCP Title");
	}

	if (p->m_expands.at("TCP Title")) {
		ImGui::Text(m.at("SPort").c_str());
		ImGui::Text(m.at("DPort").c_str());
		ImGui::Text(m.at("SeqNum").c_str());
		ImGui::Text(m.at("AckNum").c_str());
		ImGui::Text(m.at("HeaderLen").c_str());

		if (ImGui::Button(m.at("TCPFlags").c_str())) {
			p->m_expands.at("TCP Flags") = !p->m_expands.at("TCP Flags");
		}

		if (p->m_expands.at("TCP Flags")) {
			for (auto s : Data::TCPFlags) {
				ImGui::Text(m.at(s).c_str());
			}
		}
		ImGui::Text(m.at("TCPWindow").c_str());
		ImGui::Text(m.at("TCPChecksum").c_str());
		ImGui::Text(m.at("UrgentPtr").c_str());

		if (ImGui::Button(m.at("OptionTitle").c_str())) {
			p->m_expands["TCP Options"] = !p->m_expands["TCP Options"];
		}

		if (p->m_expands["TCP Options"]) {
			for (auto opt : p->m_options) {
				ImGui::Text(("\t\t" + opt->toString()).c_str());
			}
		}
	}
}

void Renderer::renderExpanded(UDP<IPV4>* p) {
	renderExpanded((IPV4*)p);

	auto map = p->getTexts();
	if (ImGui::Button(map.at("UDP Title").c_str())) {
		p->m_expands.at("UDP Title") = !p->m_expands.at("UDP Title");
	}

	if (p->m_expands.at("UDP Title")) {
		ImGui::Text(map.at("UDP SPort").c_str());
		ImGui::Text(map.at("UDP DPort").c_str());
		ImGui::Text(map.at("UDP Length").c_str());
		ImGui::Text(map.at("UDP Checksum").c_str());
		ImGui::Text(map.at("UDP Payload Length").c_str());
		ImGui::Text(map.at("UDP Payload").c_str());
	}
}

void Renderer::renderExpanded(UDP<IPV6>* p) {
	renderExpanded((IPV6*)p);

	auto map = p->getTexts();
	if (ImGui::Button(map.at("UDP Title").c_str())) {
		p->m_expands.at("UDP Title") = !p->m_expands.at("UDP Title");
	}

	if (p->m_expands.at("UDP Title")) {
		ImGui::Text(map.at("UDP SPort").c_str());
		ImGui::Text(map.at("UDP DPort").c_str());
		ImGui::Text(map.at("UDP Length").c_str());
		ImGui::Text(map.at("UDP Checksum").c_str());
		ImGui::Text(map.at("UDP Payload Length").c_str());
		ImGui::Text(map.at("UDP Payload").c_str());
	}
}

void Renderer::renderExpanded(ICMP* p) {
	renderExpanded((IPV4*)p);

	auto m = p->getTexts();

	if (ImGui::Button("Internet Control Message Control")) {
		p->m_expands.at("ICMP Title") = !p->m_expands.at("ICMP Title");
	}

	if (p->m_expands.at("ICMP Title")) {
		ImGui::Text(m.at("ICMPType").c_str());
		ImGui::Text(m.at("ICMPCode").c_str());
		ImGui::Text(m.at("ICMPChecksum").c_str());
		ImGui::Text(m.at("IDBE").c_str());
		ImGui::Text(m.at("IDLE").c_str());
		ImGui::Text(m.at("SNBE").c_str());
		ImGui::Text(m.at("SNLE").c_str());
		if (ImGui::Button(m.at("ICMPDataHeader").c_str())) {
			p->m_expands.at("ICMP Data") = !p->m_expands.at("ICMP Data");
		}

		if (p->m_expands.at("ICMP Data")) {
			ImGui::Text(m.at("ICMPData").c_str());
		}
	}
}

void Renderer::renderExpanded(ICMPV6* p) {
	renderExpanded((IPV6*)p);

	auto m = p->getTexts();

	if (ImGui::Button("Internet Control Message Control")) {
		p->m_expands.at("ICMPV6 Title") = !p->m_expands.at("ICMPV6 Title");
	}

	if (p->m_expands.at("ICMPV6 Title")) {
		ImGui::Text(m.at("ICMPV6Type").c_str());
		ImGui::Text(m.at("ICMPV6Code").c_str());
		ImGui::Text(m.at("ICMPV6Checksum").c_str());
		ImGui::Text(m.at("ICMPV6Length").c_str());
		ImGui::Text(m.at("ICMPV6Message").c_str());
	}
}

void Renderer::renderExpanded(IGMP<IPV4>* p) {
	renderExpanded((IPV4*)p);

	auto m = p->getTexts();

	if (ImGui::Button("Internet Group Management Protocol")) {
		p->m_expands.at("IGMP Title") = !p->m_expands.at("IGMP Title");
	}

	if (p->m_expands.at("IGMP Title")) {
		ImGui::Text(m.at("IGMPType").c_str());
		ImGui::Text(m.at("respTime").c_str());
		ImGui::Text(m.at("IGMPChecksum").c_str());
		ImGui::Text(m.at("multicastAddr").c_str());
	}
}

void Renderer::renderExpanded(IGMP<IPV6>* p) {
	renderExpanded((IPV6*)p);

	auto m = p->getTexts();

	if (ImGui::Button("Internet Group Management Protocol")) {
		p->m_expands.at("IGMP Title") = !p->m_expands.at("IGMP Title");
	}

	if (p->m_expands.at("IGMP Title")) {
		ImGui::Text(m.at("IGMPType").c_str());
		ImGui::Text(m.at("respTime").c_str());
		ImGui::Text(m.at("IGMPChecksum").c_str());
		ImGui::Text(m.at("multicastAddr").c_str());
	}
}