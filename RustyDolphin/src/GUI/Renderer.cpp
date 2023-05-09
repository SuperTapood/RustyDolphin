#include "Renderer.h"

#include "../Base/Data.h"

void Renderer::render(Packet* p) {
	ImGui::TableSetColumnIndex(0);
	if (ImGui::Selectable(std::to_string(p->m_idx).c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
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
	if (ImGui::Button(p->m_title.c_str())) {
		p->m_expands.at("Packet Title") = !p->m_expands.at("Packet Title");
	}

	if (p->m_expands.at("Packet Title")) {
		ImGui::Text(("\tArrival time: " + p->m_time).c_str());
		ImGui::Text(("\tDestination: " + p->m_phyDst).c_str());
		ImGui::Text(("\tSource: " + p->m_phySrc).c_str());
		ImGui::Text(("\tType: " + p->m_strType).c_str());
	}
}

void Renderer::render(ARP* p) {
	ImGui::TableSetColumnIndex(0);
	if (ImGui::Selectable(std::to_string(p->m_idx).c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
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

	if (ImGui::Button(p->m_ARPTitle.c_str())) {
		p->m_expands.at("ARP Title") = !p->m_expands.at("ARP Title");
	}

	if (p->m_expands.at("ARP Title")) {
		ImGui::Text(("\tHardware type: " + p->m_hardStr).c_str());
		ImGui::Text(("\tProtocol type: " + p->m_protoStr).c_str());
		ImGui::Text(("\tHardware size: " + std::to_string(p->m_hardSize)).c_str());
		ImGui::Text(("\tProtocol size: " + std::to_string(p->m_protoSize)).c_str());
		ImGui::Text(("\tOpcode: " + p->m_codeStr).c_str());
		ImGui::Text(("\tSender MAC Address: " + p->m_sendMAC).c_str());
		ImGui::Text(("\tSender IP Address: " + p->m_sendAddr).c_str());
		ImGui::Text(("\tTarget MAC Address: " + p->m_targetMAC).c_str());
		ImGui::Text(("\tTarget IP Address: " + p->m_targetAddr).c_str());
	}
}

void Renderer::render(IPV4* p) {
	ImGui::TableSetColumnIndex(0);
	if (ImGui::Selectable(std::to_string(p->m_idx).c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
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

	if (ImGui::Button(p->m_IPTitle.c_str())) {
		p->m_expands.at("IPV4 Title") = !p->m_expands.at("IPV4 Title");
	}

	if (p->m_expands.at("IPV4 Title")) {
		ImGui::Text("\t0100 .... = Version 4");
		ImGui::Text(p->m_headerLenStr.c_str());
		if (ImGui::Button(p->m_differServStr.c_str())) {
			p->m_expands.at("DifferServ") = !p->m_expands.at("DifferServ");
		}
		if (p->m_expands.at("DifferServ")) {
			ImGui::Text(p->m_differDSCP.c_str());
			ImGui::Text(p->m_differECN.c_str());
		}
		ImGui::Text("\tTotal Length: %d", p->m_totalLength);
		ImGui::Text(p->m_idStr.c_str());
		if (ImGui::Button(p->m_flagStr.c_str())) {
			p->m_expands.at("Flags") = !p->m_expands.at("Flags");
		}

		if (p->m_expands.at("Flags")) {
			ImGui::Text(p->m_rbitStr.c_str());
			ImGui::Text(p->m_dfbitStr.c_str());
			ImGui::Text(p->m_mfbitStr.c_str());
		}
		ImGui::Text(p->m_offsetStr.c_str());
		ImGui::Text("\tTime to Live: %d", p->m_ttl);
		ImGui::Text(p->m_protocolStr.c_str());
		ImGui::Text(p->m_headerCheckStr.c_str());
		ImGui::Text(p->m_srcStr.c_str());
		ImGui::Text(p->m_dstStr.c_str());

		if (p->m_IPoptionsCount > 0) {
			if (ImGui::Button(p->m_optsStr.c_str())) {
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
	if (ImGui::Selectable(std::to_string(p->m_idx).c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
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
	if (ImGui::Selectable(std::to_string(p->m_idx).c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
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

void Renderer::render(TCP<IPV6>* p) {
	ImGui::TableSetColumnIndex(0);
	if (ImGui::Selectable(std::to_string(p->m_idx).c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
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
	if (ImGui::Selectable(std::to_string(p->m_idx).c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
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
	if (ImGui::Selectable(std::to_string(p->m_idx).c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
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
	if (ImGui::Selectable(std::to_string(p->m_idx).c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
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

void Renderer::render(ICMPV6* p) {
	ImGui::TableSetColumnIndex(0);
	if (ImGui::Selectable(std::to_string(p->m_idx).c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
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
	if (ImGui::Selectable(std::to_string(p->m_idx).c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
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

	if (ImGui::Button("Internet Group Management Protocol")) {
		p->m_expands.at("IGMP Title") = !p->m_expands.at("IGMP Title");
	}

	if (p->m_expands.at("IGMP Title")) {
		ImGui::Text(p->m_typeStr.c_str());
		ImGui::Text(p->m_timeStr.c_str());
		ImGui::Text(p->m_checkStr.c_str());
		ImGui::Text(p->m_multiStr.c_str());
	}
}