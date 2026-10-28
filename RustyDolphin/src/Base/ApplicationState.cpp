#include "ApplicationState.h"
#include "../Core/FilterParser.h"

void ApplicationState::addPacket(std::unique_ptr<Packet> packet) {
	std::scoped_lock lock(guard);
	captured.push_back(std::move(packet));
	capIdx = static_cast<long>(captured.size());
}

void ApplicationState::clearPackets() {
	std::scoped_lock lock(guard);
	captured.clear();
	capIdx = 0;
	selected = -1;
}

void ApplicationState::processFilter() {
	auto parsed = core::parseFilter(filterTxt);
	newFilter = true;
	if (parsed) {
		filter = std::move(*parsed);
		showBadFilter = false;
		filterIssue.clear();
		return;
	}
	filter = core::FilterMap{};
	filter["num"] = "-1";
	showBadFilter = true;
	filterIssue = std::move(parsed.error());
}
