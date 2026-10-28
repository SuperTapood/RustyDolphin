#include "App.h"

#include <stdlib.h>

#include "Base/ProtocolCatalog.h"
#include "Base/MacroSettings.h"
#include "GUI/GUI.h"
#include "GUI/Renderer.h"
#include "Base/Logger.h"
#include "Networks/capture.h"
#include "Win/SDK.h"
#include "ImGuiFileDialog.h"
#include <iostream>

ApplicationState App::state;

void App::release() {
	state.doneCounting = true;
	state.doneCapturing = true;
	state.geoTerminate = true;
	if (state.captureThread.joinable()) {
		state.captureThread.join();
	}
	if (state.geoLocThread.joinable()) {
		state.geoLocThread.request_stop();
		state.geoLocThread.join();
	}
	GUI::release();
	if (state.chosenAdapter != nullptr) {
		state.chosenAdapter.reset();
	}
	state.clearPackets();
	SDK::release();
	Capture::release();
	Logger::release();
}

void App::init() {
	remove("captures/output.pcap");
	remove("captures/output.txt");
	remove("imgui.ini");
	ProtocolCatalog::init();
	Logger::init();
	Capture::init();
	SDK::init();
	GUI::init();
}

void App::adapterScreen() {
	getAdapter();

	state.showLoad = false;

	if (state.chosenAdapter == nullptr) {
		exit(-1);
	}
}

void App::captureScreen() {
	// jthread just because they join by default when they go out of scope
	state.captureThread = std::jthread([] { Capture::capturePackets(state); });

	render();

	state.doneCapturing = true;
	state.captureThread.join();
}

void App::renderAdapterMenuBar() {
	GUI::pushFont("regular");
	if (ImGui::BeginMainMenuBar()) {
		if (ImGui::BeginMenu("File")) {
			if (ImGui::MenuItem("Load")) {
				state.showLoad = true;
			}
			ImGui::EndMenu();
		}
		ImGui::EndMainMenuBar();
	}
	GUI::popFont();
}

void App::handleLoad() {
	ImGui::SetNextWindowPos(ImVec2(0, 0));
	ImGui::SetNextWindowSize(ImVec2(1280, 720));
	ImGuiFileDialog::Instance()->OpenDialog("ChooseFileDlgKey", "Choose File", ".pcapng,.pcap,", ".");

	if (ImGuiFileDialog::Instance()->Display("ChooseFileDlgKey"))
	{
		if (ImGuiFileDialog::Instance()->IsOk())
		{
			std::string filePathName = ImGuiFileDialog::Instance()->GetFilePathName();
			std::string filePath = ImGuiFileDialog::Instance()->GetCurrentPath();

			state.fileAdapter = true;
			state.chosenAdapter = Capture::load(state, filePathName);
			state.doneCounting = true;
			state.showLoad = false;
		}
		else {
			state.showLoad = false;
		}

		ImGuiFileDialog::Instance()->Close();
	}
}

void App::getAdapter() {
#ifdef CAPTURE_LIVE
	state.fileAdapter = false;
	state.chosenAdapter = Capture::createAdapter(3);
	SDK::findIP(Capture::getDev(3)->name);
	return;
#endif
#ifdef CAPTURE_SAMPLES
	state.fileAdapter = true;
	state.chosenAdapter = Capture::load(state, "samples.pcapng");
	return;
#endif
#ifdef CAPTURE_V6
	state.fileAdapter = true;
	state.chosenAdapter = Capture::load(state, "v6.pcapng");
	return;
#endif
#ifdef CAPTURE_ICMPV6
	state.fileAdapter = true;
	state.chosenAdapter = Capture::load(state, "icmpv6.pcapng");
	return;
#endif
	using std::chrono::high_resolution_clock;
	using std::chrono::duration_cast;
	using std::chrono::duration;
	using std::chrono::milliseconds;

	auto names = Capture::getDeviceNames();

	auto counts = std::vector<std::atomic_int>(names.size());

	auto threads = std::vector<std::jthread>();

	auto t1 = high_resolution_clock::now();

	for (int i = 0; i < names.size(); i++) {
		threads.emplace_back(Capture::countPackets, std::ref(state), std::ref(counts), i);
	}

	srand(static_cast<unsigned int>(time(nullptr)));

	int randomNumber = rand() % ProtocolCatalog::quotes.size();

	std::vector<float> rates;

	rates.assign(names.size(), 0.0f);

	int last = 0;
	int selected = -1;

	while (!state.doneCounting) {
		GUI::startFrame();

		if (glfwWindowShouldClose(GUI::window)) {
			exit(0);
		}

		ImGui::SetNextWindowPos(ImVec2(0, 20));
		ImGui::SetNextWindowSize(ImVec2(1280, 700));
		ImGui::Begin("Adapter Selection Window", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

		renderAdapterMenuBar();

		if (state.showLoad) {
			GUI::pushFont("regular");
			handleLoad();
			GUI::popFont();
		}

		ImGui::SetCursorPos(ImVec2(340, 0));
		GUI::pushFont("title");
		GUI::centerText("Welcome to RustyDolphin");
		GUI::popFont();

		GUI::pushFont("quote");
		GUI::centerText(ProtocolCatalog::quotes.at(randomNumber));
		GUI::popFont();

		GUI::pushFont("adapters");
		ImGui::SetCursorPosY(150);
		ImGui::Text("Choose the adapter you'd like to use:");

		auto t2 = high_resolution_clock::now();
		auto ms_int = duration_cast<milliseconds>(t2 - t1);
		auto secs = (double)ms_int.count() / 1000;

		if (secs >= ((double)last / 5.0)) {
			for (int i = 0; i < rates.size(); i++) {
				rates.at(i) = static_cast<float>(counts.at(i).load(std::memory_order_relaxed) / secs);
			}
			last++;
		}

		std::stringstream ss;
		for (int i = 0; i < names.size(); i++) {
			ImGui::SetCursorPosX(150);
			ss << names.at(i) << " (Packet Rate: " << rates.at(i) << " per second)";
			if (ImGui::Button(ss.str().c_str())) {
				selected = i;
			}
			ss.str("");
		}

		if (selected != -1) {
			ImGui::OpenPopup("AdapterSelectPopup");

			ImGui::SetNextWindowSize(ImVec2(600, 500));
			ImGui::SetNextWindowPos(ImVec2(640 - 300, 360 - 250));
			if (ImGui::BeginPopupModal("AdapterSelectPopup", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar))
			{
				GUI::centerText("Are you sure you want this adapter?");
				ImGui::SetCursorPosY(350);
				if (GUI::centerButton("Yes")) {
					state.doneCounting = true;
					GUI::popFont();
					ImGui::EndPopup();
					ImGui::End();
					GUI::endFrame();
					break;
				}
				ImGui::SetCursorPosY(430);
				if (GUI::centerButton("No")) {
					selected = -1;
					ImGui::CloseCurrentPopup();
				}
				ImGui::EndPopup();
			}
		}

		GUI::popFont();

		ImGui::End();

		GUI::endFrame();
	}

	// std::jthread joins automatically when the vector leaves scope.
	threads.clear();

	if (state.chosenAdapter != nullptr) {
		return;
	}

	state.fileAdapter = false;

	if (selected != -1) {
		state.chosenAdapter = Capture::createAdapter(selected);
	}
	if (selected != -1) {
		SDK::findIP(Capture::getDev(selected)->name);
	}
}

void App::handleStop() {
	GUI::pushFont("adapters");
	ImGui::OpenPopup("StopCapture");

	ImGui::SetNextWindowSize(ImVec2(600, 500));
	ImGui::SetNextWindowPos(ImVec2(640 - 300, 360 - 250));
	if (ImGui::BeginPopupModal("StopCapture", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar))
	{
		GUI::centerText("Are you sure you want stop the current capture?");
		ImGui::SetCursorPosY(350);
		if (GUI::centerButton("Yes")) {
			state.doneCapturing = true;
			state.showStop = false;
		}
		ImGui::SetCursorPosY(430);
		if (GUI::centerButton("No")) {
			state.showStop = false;
		}
		ImGui::EndPopup();
	}
	GUI::popFont();
}

void App::handleStart() {
	GUI::pushFont("adapters");
	ImGui::OpenPopup("StartCapture");

	ImGui::SetNextWindowSize(ImVec2(600, 500));
	ImGui::SetNextWindowPos(ImVec2(340, 110));
	if (ImGui::BeginPopupModal("StartCapture", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar))
	{
		GUI::centerText("You have an ongoing capture.");
		GUI::centerText("do you want to start another one?");
		GUI::centerText("(the current one will be reset)");
		ImGui::SetCursorPosY(350);
		if (GUI::centerButton("Yes")) {
			state.doneCapturing = true;
			state.selected = -1;
			state.showStart = false;
			state.captureThread.join();
			state.clearPackets();
			state.doneCapturing = false;
			state.captureThread = std::jthread([] { Capture::capturePackets(state); });
		}
		ImGui::SetCursorPosY(430);
		if (GUI::centerButton("No")) {
			state.showStart = false;
		}
		ImGui::EndPopup();
	}
	GUI::popFont();
}

void App::handleStartFile() {
	GUI::pushFont("adapters");
	ImGui::OpenPopup("StartCapture");

	ImGui::SetNextWindowSize(ImVec2(600, 500));
	ImGui::SetNextWindowPos(ImVec2(640 - 300, 360 - 250));
	if (ImGui::BeginPopupModal("StartCapture", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar))
	{
		GUI::centerText("Your current capture is from a file.");
		GUI::centerText("Would you like to replay it from the beginning?");
		ImGui::SetCursorPosY(350);
		if (GUI::centerButton("Yes")) {
			state.doneCapturing = true;
			state.selected = -1;
			state.showStart = false;
			state.captureThread.join();
			state.clearPackets();
			if (state.chosenAdapter != nullptr) {
				state.chosenAdapter.reset();
			}
			state.doneCapturing = false;
			state.doneLoading = false;
			state.chosenAdapter = Capture::load(state, state.loadedCapturePath);
			if (state.chosenAdapter == nullptr) {
				state.doneCapturing = true;
				return;
			}
			state.captureThread = std::jthread([] { Capture::capturePackets(state); });
		}
		ImGui::SetCursorPosY(430);
		if (GUI::centerButton("No")) {
			state.showStart = false;
		}
		ImGui::EndPopup();
	}
	GUI::popFont();
}

void App::handleSaveGoing() {
	GUI::pushFont("adapters");
	ImGui::OpenPopup("Save Packets");
	ImGui::SetNextWindowSize(ImVec2(600, 500));
	ImGui::SetNextWindowPos(ImVec2(640 - 300, 360 - 250));
	if (ImGui::BeginPopupModal("Save Packets", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar))
	{
		GUI::centerText("Your current capture is still on going.");
		GUI::centerText("Stop the current capture to save.");
		ImGui::SetCursorPosY(350);
		if (GUI::centerButton("OK")) {
			state.showSave = false;
		}
		ImGui::EndPopup();
	}
	GUI::popFont();
}

void App::handleSave() {
	ImGui::SetNextWindowPos(ImVec2(0, 0));
	ImGui::SetNextWindowSize(ImVec2(1280, 720));
	ImGuiFileDialog::Instance()->OpenDialog("ChooseFileDlgKey", "Choose File", ".pcapng,.pcap,", ".", 1, nullptr, ImGuiFileDialogFlags_ConfirmOverwrite);

	if (ImGuiFileDialog::Instance()->Display("ChooseFileDlgKey"))
	{
		if (ImGuiFileDialog::Instance()->IsOk())
		{
			std::string filePathName = ImGuiFileDialog::Instance()->GetFilePathName();
			std::string filePath = ImGuiFileDialog::Instance()->GetCurrentPath();

			Capture::dumpAll(state, filePathName);

			state.showSave = false;
		}
		else {
			state.showSave = false;
		}

		ImGuiFileDialog::Instance()->Close();
	}
}

void App::handleLoadCapture() {
	ImGui::SetNextWindowPos(ImVec2(0, 0));
	ImGui::SetNextWindowSize(ImVec2(1280, 720));
	ImGuiFileDialog::Instance()->OpenDialog("ChooseFileDlgKey", "Choose File", ".pcapng,.pcap,", ".");

	if (ImGuiFileDialog::Instance()->Display("ChooseFileDlgKey"))
	{
		if (ImGuiFileDialog::Instance()->IsOk())
		{
			std::string filePathName = ImGuiFileDialog::Instance()->GetFilePathName();
			std::string filePath = ImGuiFileDialog::Instance()->GetCurrentPath();

			state.doneCapturing = true;
			state.selected = -1;
			state.showStart = false;
			state.captureThread.join();
			state.clearPackets();
			state.doneCapturing = false;
			state.doneLoading = false;
			state.fileAdapter = true;
			state.showLoad = false;
			if (state.chosenAdapter != nullptr) {
				state.chosenAdapter.reset();
			}
			state.chosenAdapter = Capture::load(state, filePathName);
			if (state.chosenAdapter != nullptr) {
				state.captureThread = std::jthread([] { Capture::capturePackets(state); });
			}
		}
		else {
			state.showLoad = false;
		}

		ImGuiFileDialog::Instance()->Close();
	}
}

void App::filterHelp() {
	GUI::pushFont("adapters");
	ImGui::OpenPopup("Filter Help");
	ImGui::SetNextWindowSize(ImVec2(1080, 520));
	ImGui::SetNextWindowPos(ImVec2(100, 100));
	if (ImGui::BeginPopupModal("Filter Help", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar))
	{
		GUI::centerText("Filter Documentation");
		GUI::centerText("below are the allowed filters and the values they accept:");
		ImGui::Text("num");
		GUI::pushFont("regular");
		ImGui::Text("the number of the packet in the packet stream. (this filter only shows one packet)");
		ImGui::Text("for example, if you wanted to only see packet number 68 you can type: 'num=68'");
		GUI::popFont();
		ImGui::Text("len");
		GUI::pushFont("regular");
		ImGui::Text("the overall length of the packet in bytes (bytes on wire)");
		ImGui::Text("for example, if you wanted to only see packets containing exactly 60 bytes you can type: 'len=60'");
		GUI::popFont();
		ImGui::Text("ip");
		GUI::pushFont("regular");
		ImGui::Text("the type of meta-protocol used in the packet itself (called ip for brevity, but this also includes arp)");
		ImGui::Text("for example, if you wanted to only see arp packets you can type: 'ip=arp'");
		GUI::popFont();
		ImGui::Text("proto");
		GUI::pushFont("regular");
		ImGui::Text("the type of protocol used in the packet itself (such as TCP, UDP, ICMP, etc)");
		ImGui::Text("for example, if you wanted to only see packets which use the IGMP protocol you can type: 'proto=igmp'");
		GUI::popFont();
		ImGui::Text("saddr");
		GUI::pushFont("regular");
		ImGui::Text("the address (whether it is IPv4, IPv6, or MAC depends on the packet) of the packet's source");
		ImGui::Text("for example, if you wanted to only see packets which came from 10.0.11.69 you can type: 'saddr=10.0.11.69'");
		GUI::popFont();
		ImGui::Text("daddr");
		GUI::pushFont("regular");
		ImGui::Text("the address (whether it is IPv4, IPv6, or MAC depends on the packet) of the packet's destination");
		ImGui::Text("for example, if you wanted to only see packets which are addressed to MAC broadcast you can type: 'daddr=ff:ff:ff:ff:ff:ff'");
		GUI::popFont();
		ImGui::Text("sport");
		GUI::pushFont("regular");
		ImGui::Text("the port from which the packet originated");
		ImGui::Text("for example, if you wanted to only see packets which came from port 443 you can type: 'sport=443'");
		GUI::popFont();
		ImGui::Text("dport");
		GUI::pushFont("regular");
		ImGui::Text("the port to which the packet is headed");
		ImGui::Text("for example, if you wanted to only see packets headed to port 42069 you can type: 'dport=42069'");
		GUI::popFont();
		ImGui::Text("proc");
		GUI::pushFont("regular");
		ImGui::Text("the process which sent the packet (due to the way the process detecting works, only tcp and udp connections are detected, and some mistakes may be made)");
		ImGui::Text("for example, if you wanted to only see packets sent / received by Google's Chrome you can: 'proc=chrome.exe'");
		GUI::popFont();
		ImGui::Text("notes");
		GUI::pushFont("regular");
		ImGui::Text("-in order to chain multiple filters together, use commas to sepearte them: 'proto=tcp, proc=msedge.exe, len=42'");
		ImGui::Text("-leading and trailing spaces are trimmed from filter inputs to reduce the amount of headache :)");
		ImGui::Text("-if a bad filter is given, no packet will be presented");
		ImGui::Text("-each presented packet has to pass every filter. you cannot use filters to present both tcp and udp packets for example by using");
		ImGui::Text("'proto=tcp, proto=udp'. only udp packets will be presented as its the last filter");
		GUI::popFont();
		ImGui::Text("\n\n");
		if (GUI::centerButton("OK")) {
			state.showFilterHelp = false;
		}
		ImGui::EndPopup();
	}
	GUI::popFont();
}

void App::renderCaptureMenuBar() {
	if (ImGui::BeginMainMenuBar()) {
		if (ImGui::BeginMenu("File")) {
			if (ImGui::MenuItem("Load")) {
				state.showLoad = true;
			}
			if (ImGui::MenuItem("Save")) {
				state.showSave = true;
			}
			ImGui::EndMenu();
		}
		if (ImGui::BeginMenu("Capture")) {
			if (ImGui::MenuItem("Start")) {
				state.showStart = true;
			}
			if (ImGui::MenuItem("Stop")) {
				state.showStop = true;
			}
			ImGui::EndMenu();
		}
		if (ImGui::BeginMenu("Help")) {
			if (ImGui::MenuItem("Filter Docs")) {
				state.showFilterHelp = true;
			}
			ImGui::EndMenu();
		}
		std::string text = std::format("total packet captured: {} | packets displayed: {}", state.capIdx.load(), state.displayed);
		ImVec2 textSize = ImGui::CalcTextSize(text.c_str());
		ImGui::SetCursorPosX(ImGui::GetWindowWidth() - textSize.x);
		ImGui::Text(text.c_str());
		ImGui::EndMainMenuBar();
	}
}

constexpr auto columns = 7;

void App::renderTable() {
	std::vector<Packet*> packets;
	{
		std::scoped_lock guard(state.guard);
		packets.reserve(state.captured.size());
		for (const auto& packet : state.captured) packets.push_back(packet.get());
	}
	if (ImGui::BeginTable("Packet Table", columns, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg))
	{
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn(("No."), ImGuiTableColumnFlags_WidthFixed, 80.0f);
		ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 90.0f);
		ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 200.0f);
		ImGui::TableSetupColumn("Destination", ImGuiTableColumnFlags_WidthFixed, 200.0f);
		ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthFixed, 100.0f);
		ImGui::TableSetupColumn("Length", ImGuiTableColumnFlags_WidthFixed, 50.0f);
		ImGui::TableSetupColumn("Info", ImGuiTableColumnFlags_WidthFixed, 560.0f);
		ImGui::TableHeadersRow();

		std::vector<Packet*> visible;
		visible.reserve(packets.size());
		for (auto* packet : packets) {
			Renderer renderer(state);
			if (renderer.filter(packet)) visible.push_back(packet);
		}
		state.displayed = static_cast<long>(visible.size());

		ImGuiListClipper clipper;
		clipper.Begin(static_cast<int>(visible.size()));
		while (clipper.Step()) {
			for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
				auto* packet = visible[static_cast<size_t>(row)];
				ImGui::TableNextRow();
				Renderer renderer(state);
				renderer.renderPacket(packet);
				if (static_cast<int>(packet->m_idx) == state.selected) {
					ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
						ImGui::ColorConvertFloat4ToU32(ImVec4(56.f / 255.f, 123.f / 255.f, 203.f / 255.f, 0.5f)));
				}
			}
		}

		// after one frame the filter is no longer new
		state.newFilter = false;
		ImGui::EndTable();
	}
	ImGui::End();
}

void App::renderExpandedPacket() {
	Packet* selectedPacket = nullptr;
	{
		std::scoped_lock guard(state.guard);
		if (state.selected >= 0 && static_cast<size_t>(state.selected) < state.captured.size()) {
			selectedPacket = state.captured[static_cast<size_t>(state.selected)].get();
		}
	}
	if (selectedPacket == nullptr) {
		state.selected = -1;
		return;
	}
	ImGui::SetNextWindowPos(ImVec2(0, 380));
	ImGui::SetNextWindowSize(ImVec2(780, 340));
	ImGui::Begin("Expanded Packet", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

		Renderer renderer(state);
		renderer.renderDetails(selectedPacket);

	ImGui::End();

	ImGui::SetNextWindowPos(ImVec2(780, 380));
	ImGui::SetNextWindowSize(ImVec2(500, 340));
	ImGui::Begin("Packet Data View", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

	std::string str;

	GUI::pushFont("hexView");

	auto p = selectedPacket;

	int inc = 0;

	auto hexData = p->getTexts().at("hexData");

	for (int i = 0; i < hexData.size(); i += 2) {
		std::string byte = hexData.substr(i, 2);
		if (i % 32 == 0 && i > 0) {
			std::stringstream ss;
			ss << std::hex << std::setw(4) << std::setfill('0') << inc;
			ImGui::SetCursorPosX(10);
			ImGui::Text((ss.str() + " " + str).c_str());
			str = " " + byte;
			inc += 16;
		}
		else {
			str += " " + byte;
		}
	}
	ImGui::SetCursorPosX(10);
	std::stringstream ss;
	ss << std::hex << std::setw(4) << std::setfill('0') << inc;
	ImGui::Text((ss.str() + " " + str).c_str());

	GUI::popFont();

	ImGui::End();
}

void App::alertFilter() {
	GUI::pushFont("adapters");
	ImGui::OpenPopup("Bad Filter");
	ImGui::SetNextWindowSize(ImVec2(600, 500));
	ImGui::SetNextWindowPos(ImVec2(640 - 300, 360 - 250));
	if (ImGui::BeginPopupModal("Bad Filter", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar))
	{
		GUI::centerText("Your filter is not correct:");
		GUI::centerText(state.filterIssue.c_str());
		GUI::centerText("\nIf you need help with filtering");
		GUI::centerText("You can use the documentation:");
		GUI::centerText("Help->Filter Docs");
		ImGui::SetCursorPosY(350);
		if (GUI::centerButton("OK")) {
			state.showBadFilter = false;
		}
		ImGui::EndPopup();
	}
	GUI::popFont();
}

void App::renderFilterBox() {
	ImGui::InputText("##", state.filterTxt, IM_ARRAYSIZE(state.filterTxt));

	ImGui::SameLine();

	if (ImGui::Button("Apply")) {
		state.processFilter();
	}

	ImGui::SameLine();

	if (ImGui::Button("Clear")) {
		state.filterTxt[0] = '\0';
		state.processFilter();
	}

	if (state.showBadFilter) {
		alertFilter();
	}
}

void App::geoTable() {
	std::scoped_lock guard(state.geoGuard);
	if (ImGui::BeginTable("Geo Table", columns, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg,
		ImGui::GetContentRegionAvail()))
	{
		GUI::pushFont("regular");
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("Hop Number", ImGuiTableColumnFlags_WidthFixed, 90.0f);
		ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 120.0f);
		ImGui::TableSetupColumn("reverse DNS", ImGuiTableColumnFlags_WidthFixed, 320.0f);
		ImGui::TableSetupColumn("ISP", ImGuiTableColumnFlags_WidthFixed, 300.0f);
		ImGui::TableSetupColumn("Latitude", ImGuiTableColumnFlags_WidthFixed, 110.0f);
		ImGui::TableSetupColumn("Longitude", ImGuiTableColumnFlags_WidthFixed, 110.0f);
		ImGui::TableSetupColumn("Timezone", ImGuiTableColumnFlags_WidthFixed, 180.0f);
		ImGui::TableHeadersRow();

		for (size_t row = 0; row < state.locs.size(); row++) {
			ImGui::TableNextRow();
			const auto& location = state.locs.at(row);
			ImGui::TableSetColumnIndex(0);
			ImGui::Text("%zu", row + 1);
			ImGui::TableSetColumnIndex(1);
			ImGui::TextUnformatted(location.ip.c_str());
			ImGui::TableSetColumnIndex(2);
			ImGui::TextUnformatted(location.reverseDns.c_str());
			ImGui::TableSetColumnIndex(3);
			ImGui::TextUnformatted(location.isp.c_str());
			ImGui::TableSetColumnIndex(4);
			ImGui::TextUnformatted(location.latitude ? std::to_string(*location.latitude).c_str() : "Unknown");
			ImGui::TableSetColumnIndex(5);
			ImGui::TextUnformatted(location.longitude ? std::to_string(*location.longitude).c_str() : "Unknown");
			ImGui::TableSetColumnIndex(6);
			ImGui::TextUnformatted(location.timezone.c_str());
		}

		GUI::popFont();
		ImGui::EndTable();
	}
}

void App::showHops() {
	std::scoped_lock guard(state.geoGuard);
	const ImVec2 available = ImGui::GetContentRegionAvail();
	const float scale = (std::max)(0.1f, (std::min)(available.x / 1024.0f, available.y / 794.0f));
	const ImVec2 imageSize(1024.0f * scale, 794.0f * scale);
	auto xShift = (available.x - imageSize.x) * 0.5f;
	ImGui::SetCursorPosX(xShift);
	const ImVec2 imageTopLeft = ImGui::GetCursorScreenPos();
	ImGui::Image((void*)(intptr_t)GUI::earthTex, imageSize);
	std::pair<double, double> lastCoords = { -1, -1 };
	ImDrawList* draw_list = ImGui::GetWindowDrawList();
	constexpr auto r = 4;
	for (size_t row = 0; row < state.locs.size(); row++) {
		const auto& location = state.locs.at(row);
		if (!location.longitude || !location.latitude) continue;
		auto [x, y] = ProtocolCatalog::mercatorProjection(*location.longitude, *location.latitude);
		ImVec2 circle_pos = ImVec2(
			imageTopLeft.x + static_cast<float>(x) * scale,
			imageTopLeft.y + static_cast<float>(y) * scale);
		draw_list->AddCircleFilled(circle_pos, r, IM_COL32(255, 0, 0, 255));

		if (lastCoords.first != -1) {
			draw_list->AddLine(
				ImVec2(static_cast<float>(lastCoords.first), static_cast<float>(lastCoords.second)),
				circle_pos, IM_COL32(255, 0, 0, 255), r / 2.0f);
		}

		lastCoords.first = circle_pos.x;
		lastCoords.second = circle_pos.y;
	}
}

void App::showGeoTrace() {
	GUI::pushFont("adapters");
	ImGui::OpenPopup("GeoLoc");
	ImGui::SetNextWindowSize(ImVec2(1280, 720));
	ImGui::SetNextWindowPos(ImVec2(0, 0));
	if (ImGui::BeginPopupModal("GeoLoc", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar))
	{
		std::string hopAddress;
		std::string geoError;
		{
			std::scoped_lock guard(state.geoGuard);
			hopAddress = state.hopAddr;
			geoError = state.geoError;
		}
		GUI::centerText(std::format("Route geolocation for {}", hopAddress).c_str());
		if (state.geoState.load() == 1) {
			GUI::centerText("Querying Address...");
		}
		else if (state.geoState.load() == 2) {
			GUI::centerText("Processing Replies...");
		}
		else if (state.geoState.load() == 3) {
			GUI::centerText("No public geolocation data was available for this address.");
		}
		else if (state.geoState.load() == 4) {
			GUI::centerText("Processing Done");
		}
		if (!geoError.empty()) {
			ImGui::TextWrapped("Some lookups failed: %s", geoError.c_str());
		}
		if (ImGui::BeginTabBar("Geo views")) {
			if (ImGui::BeginTabItem("Locations")) {
				geoTable();
				ImGui::EndTabItem();
			}
			if (ImGui::BeginTabItem("Map")) {
				showHops();
				ImGui::EndTabItem();
			}
			ImGui::EndTabBar();
		}

		const bool done = state.geoDone.load();
		if (GUI::centerButton(done ? "Close" : "Cancel")) {
			if (state.geoLocThread.joinable()) {
				state.geoLocThread.request_stop();
				state.geoLocThread.join();
			}
			state.showGeoTrace = -1;
			std::scoped_lock guard(state.geoGuard);
			state.locs.clear();
		}
	}
	ImGui::End();
	GUI::popFont();
}

void App::render() {
	const auto upArrow = ImGui::GetKeyIndex(ImGuiKey_UpArrow);
	const auto downArrow = ImGui::GetKeyIndex(ImGuiKey_DownArrow);
	while (!glfwWindowShouldClose(GUI::window))
	{
		GUI::startFrame();

		GUI::pushFont("regular");

		ImGui::SetNextWindowPos(ImVec2(0, 20));
		ImGui::SetNextWindowSize(ImVec2(1280, 360));
		ImGui::Begin("Packet Table Window", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

		renderCaptureMenuBar();

		renderFilterBox();

		renderTable();

		if (state.showFilterHelp) {
			filterHelp();
		}

		if (state.selected != -1) {
			renderExpandedPacket();
		}

		if (state.showStop) {
			handleStop();
		}
		else if (state.showStart && !state.fileAdapter) {
			handleStart();
		}
		else if (state.showStart && state.fileAdapter) {
			handleStartFile();
		}

		else if (!state.doneCapturing && state.showSave) {
			handleSaveGoing();
		}
		else if (state.doneCapturing && state.showSave) {
			handleSave();
		}

		else if (state.showLoad) {
			handleLoadCapture();
		}

		else if (state.showGeoTrace != -1) {
			showGeoTrace();
		}

		GUI::popFont();

		if (ImGui::IsKeyPressed(upArrow)) {
			state.selected = max(state.selected - 1, 0);
		}

		if (ImGui::IsKeyPressed(downArrow) && state.capIdx.load() > 0) {
			state.selected = min(state.selected + 1, static_cast<int>(state.capIdx.load() - 1));
		}

		GUI::endFrame();
	}
}
