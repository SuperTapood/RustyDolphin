#include "Renderer.h"

#include "../Base/Data.h"


void Renderer::render(Packet* p) {
	ImGui::TableSetColumnIndex(0);
	if (ImGui::Selectable(std::to_string(p->idx).c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
		Data::selected = p->idx;
	}
	ImGui::TableSetColumnIndex(1);
	ImGui::Text("%d", p->m_epoch);
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
	if (ImGui::Button(p->m_expands.at(0) ? ">" : "v")) {
		p->m_expands.at(0) = !p->m_expands.at(0);
	}

	ImGui::SameLine();

	ImGui::Text(p->m_title.c_str());

	if (p->m_expands.at(0)) {
		ImGui::Text(("\tArrival time: " + p->m_time).c_str());
		ImGui::Text(("\tDestination: " + p->m_phyDst).c_str());
		ImGui::Text(("\tSource: " + p->m_phySrc).c_str());
		ImGui::Text(("\tType: " + p->m_strType).c_str());
	}


	//// Create a new text box and a button.
	//ImGui::Text("This is a text box.");
	//ImGui::SameLine();
	//if (ImGui::Checkbox("Expand")) {
	//	ImGui::Text("This is a longer text box.");
	//}

	//// Create a new toggleable item.
	//bool expanded = ImGui::Checkbox("Expand");

	//// Render the text box.
	//ImGui::Text("This is a text box.");

	//// If the toggleable item is checked, render more text.
	//if (expanded) {
	//	ImGui::Text("This is more text.");
	//}

	//// Call ImGui::Begin() to start a new Dear ImGui window.
	//ImGui::Begin("My Window");

	//// Render the text box and the button.
	//ImGui::Text("This is a text box.");
	//ImGui::SameLine();
	//ImGui::Button("Expand");

	//// Call ImGui::End() to end the Dear ImGui window.
	//ImGui::End();
}

void Renderer::render(ARP* p) {
	ImGui::TableSetColumnIndex(0);
	if (ImGui::Selectable(std::to_string(p->idx).c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
		Data::selected = p->idx;
	}
	ImGui::TableSetColumnIndex(1);
	ImGui::Text("%d", p->m_epoch);
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

void Renderer::render(TCP<IPV4>* p) {
	ImGui::TableSetColumnIndex(0);
	if (ImGui::Selectable(std::to_string(p->idx).c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
		Data::selected = p->idx;
	}
	ImGui::TableSetColumnIndex(1);
	ImGui::Text("%d", p->m_epoch);
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
	if (ImGui::Selectable(std::to_string(p->idx).c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
		Data::selected = p->idx;
	}
	ImGui::TableSetColumnIndex(1);
	ImGui::Text("%d", p->m_epoch);
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
	if (ImGui::Selectable(std::to_string(p->idx).c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
		Data::selected = p->idx;
	}
	ImGui::TableSetColumnIndex(1);
	ImGui::Text("%d", p->m_epoch);
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
	if (ImGui::Selectable(std::to_string(p->idx).c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
		Data::selected = p->idx;
	}
	ImGui::TableSetColumnIndex(1);
	ImGui::Text("%d", p->m_epoch);
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
	if (ImGui::Selectable(std::to_string(p->idx).c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
		Data::selected = p->idx;
	}
	ImGui::TableSetColumnIndex(1);
	ImGui::Text("%d", p->m_epoch);
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
	if (ImGui::Selectable(std::to_string(p->idx).c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
		Data::selected = p->idx;
	}
	ImGui::TableSetColumnIndex(1);
	ImGui::Text("%d", p->m_epoch);
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