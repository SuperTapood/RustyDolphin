#include "Renderer.h"

#include "../Base/Data.h"

void Renderer::render(Packet* p) {
	ImGui::TableSetColumnIndex(0);
	if (ImGui::Selectable(p->m_idxStr.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
		Data::selected = p->m_idx;
	}
	ImGui::TableSetColumnIndex(1);
	ImGui::Text("%f", p->m_epoch);
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

void Renderer::render(ARP* p) {
	ImGui::TableSetColumnIndex(0);
	if (ImGui::Selectable(p->m_idxStr.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
		Data::selected = p->m_idx;
	}
	ImGui::TableSetColumnIndex(1);
	ImGui::Text("%f", p->m_epoch);
	ImGui::TableSetColumnIndex(2);
	ImGui::Text(p->m_phySrc.c_str());
	ImGui::TableSetColumnIndex(3);
	ImGui::Text(p->m_phyDst.c_str());
	ImGui::TableSetColumnIndex(4);
	ImGui::Text("ARP");
	ImGui::TableSetColumnIndex(5);
	ImGui::Text("%d", p->m_len);
	ImGui::TableSetColumnIndex(6);
	ImGui::Text(p->m_description.c_str());
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
	ImGui::Text("%f", p->m_epoch);
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
		ImGui::Text("\t0100 .... = Version 4");
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
				for (int i = 0; i < p->m_optButtons.size(); i++) {
					auto b = p->m_optButtons.at(i);
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
	}
}

void Renderer::render(IPV6* p) {
	ImGui::TableSetColumnIndex(0);
	if (ImGui::Selectable(p->m_idxStr.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
		Data::selected = p->m_idx;
	}
	ImGui::TableSetColumnIndex(1);
	ImGui::Text("%f", p->m_epoch);
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

void Renderer::render(TCP<IPV4>* p) {
	ImGui::TableSetColumnIndex(0);
	if (ImGui::Selectable(p->m_idxStr.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
		Data::selected = p->m_idx;
	}
	ImGui::TableSetColumnIndex(1);
	ImGui::Text("%f", p->m_epoch);
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

void Renderer::renderExpanded(TCP<IPV4>* p) {
	renderExpanded((IPV4*)p);

	/*if (ImGui::Button(p->m_TCPTitle.c_str())) {
		p->m_expands.at("TCP Title") = !p->m_expands.at("TCP Title");
	}

	if (p->m_expands.at("TCP Title")) {

	}*/
}

void Renderer::render(TCP<IPV6>* p) {
	ImGui::TableSetColumnIndex(0);
	if (ImGui::Selectable(p->m_idxStr.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
		Data::selected = p->m_idx;
	}
	ImGui::TableSetColumnIndex(1);
	ImGui::Text("%f", p->m_epoch);
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

void Renderer::render(UDP<IPV4>* p) {
	ImGui::TableSetColumnIndex(0);
	if (ImGui::Selectable(p->m_idxStr.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
		Data::selected = p->m_idx;
	}
	ImGui::TableSetColumnIndex(1);
	ImGui::Text("%f", p->m_epoch);
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

void Renderer::render(UDP<IPV6>* p) {
	ImGui::TableSetColumnIndex(0);
	if (ImGui::Selectable(p->m_idxStr.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
		Data::selected = p->m_idx;
	}
	ImGui::TableSetColumnIndex(1);
	ImGui::Text("%f", p->m_epoch);
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

void Renderer::render(ICMP* p) {
	ImGui::TableSetColumnIndex(0);
	if (ImGui::Selectable(p->m_idxStr.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
		Data::selected = p->m_idx;
	}
	ImGui::TableSetColumnIndex(1);
	ImGui::Text("%f", p->m_epoch);
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

void Renderer::render(ICMPV6* p) {
	ImGui::TableSetColumnIndex(0);
	if (ImGui::Selectable(p->m_idxStr.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
		Data::selected = p->m_idx;
	}
	ImGui::TableSetColumnIndex(1);
	ImGui::Text("%f", p->m_epoch);
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


void Renderer::render(IGMP<IPV4>* p) {
	ImGui::TableSetColumnIndex(0);
	if (ImGui::Selectable(p->m_idxStr.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
		Data::selected = p->m_idx;
	}
	ImGui::TableSetColumnIndex(1);
	ImGui::Text("%f", p->m_epoch);
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