#include "Renderer.h"


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
	ImGui::Text("base packet :)");
}