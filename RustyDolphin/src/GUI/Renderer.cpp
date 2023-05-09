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
		p->m_expands.at(0) = !p->m_expands.at(0);
	}

	if (p->m_expands.at(0)) {
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
		p->m_expands.at(1) = !p->m_expands.at(1);
	}

	if (p->m_expands.at(1)) {
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