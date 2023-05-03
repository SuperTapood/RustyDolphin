#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <iostream>
#include <cstdio>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <Winsock2.h>
#include <Windows.h>
#include "Base/Base.h"
#include "Networks/Networks.h"
#include "Win/Win.h"
#include <cstdint>
#include <thread>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <GLFW/glfw3.h>
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <fstream>
#include <string>
#include <IcmpAPI.h>
#include <GLFW/glfw3native.h>
#include "GUI/GUI.h"
#include "ImGuiFileDialog.h"

static std::atomic<bool> done(false);

void release() {
	done = true;
	Logger::release();
	Capture::release();
	SDK::release();
	GUI::release();
}

void init() {
	atexit(release);
	Logger::init();
	Capture::init();
	SDK::init();
	GUI::init();
}

void countPackets(std::vector<int>* counts, int adapterIdx) {
	auto d = Capture::getDev(adapterIdx);
	auto adhandle = Capture::createAdapter(adapterIdx, true);
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	int r;

	while ((r = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (done) {
			break;
		}
		if (r == 0) {
			continue;
		}

		counts->at(adapterIdx) += 1;
	}

	pcap_close(adhandle);
}

void sampleCallback(pcap_pkthdr* header, const u_char* pkt_data, std::string filename) {
	auto p = fromRaw(header, pkt_data);

	std::size_t pos = filename.find('.');
	if (pos != std::string::npos) {
		filename.erase(pos);
	}

	std::ofstream file(filename + ".txt", std::ios_base::app);

	if (!file) {
		std::cerr << "Error opening file: " << filename + ".txt" << '\n';
		exit(69);
	}

	file << p->jsonify().dump(4) << "\n";

	// std::cout << p->jsonify().dump(4) << std::endl;

	std::cout << p->toString() << std::endl;
}

int sample() {
	std::cout << "hold on. rates are being captured.\n";

	int constexpr seconds = 1;

	auto names = Capture::getDeviceNames(true);

	auto counts = std::vector<int>(names->size(), 0);

	auto threads = std::vector<std::thread*>();

	for (int i = 0; i < names->size(); i++) {
		threads.push_back(new std::thread(countPackets, &counts, i));
	}

	std::this_thread::sleep_for(std::chrono::seconds(seconds));
	done = true;

	std::for_each(threads.cbegin(), threads.cend(), [](std::thread* t) {t->join(); });

	std::cout << "the following adapters were detected:\n";

	for (int i = 0; i < names->size(); i++) {
		std::cout << i + 1 << ". " << names->at(i) << "(packets rate: " << ((float)counts.at(i) / (float)seconds) << " per second)\n";
	}

	/*for (int i = 0; i < names->size(); i++) {
		std::cout << i + 1 << ". " << names->at(i) << "\n";
	}*/

	int adapterIdx = 0;

	std::cout << "Enter the number of the adapter you wish to use: ";

	std::cin >> adapterIdx;

	if (adapterIdx <= 0 || adapterIdx > names->size()) {
		std::cout << "\nnah man that's a bad adapter index\nbetter luck next time\n";
		return 0;
	}

	// we need it zero indexed
	adapterIdx -= 1;

	std::cout << "\nDo you want to enable promiscuous mode? (Y/N): ";

	std::string temp;

	std::cin >> temp;

	bool promiscuous = temp == "Y";

	std::cout << "\nHow Many packets do you want to capture: ";

	int maxPackets;

	std::cin >> maxPackets;

	if (maxPackets <= 0) {
		std::cout << "\nno\n";
		return 0;
	}

	std::cout << "\nwould you like to apply a filter? if so enter it if not enter X: ";

	std::string filter;

	std::cin >> filter;

	if (filter == "X") {
		filter = "";
	}

	Capture::sample(adapterIdx, sampleCallback, promiscuous, maxPackets, filter);
}

int main(int argc, char* argv[])
{
	init();

	if (argc > 1) {
		std::string arg = argv[1];

		if (arg == "curl") {
			std::string addr;
			std::cout << "enter the address to geo locate: ";
			std::cin >> addr;
			auto j = SDK::geoLocate(addr);
			std::cout << j.dump(4);
			return 0;
		}

		return 0;
	}

	// return sample();

	// Capture::sample(3, sampleCallback, true, 1, "udp");

	remove("captures/output.pcap");
	remove("captures/output.txt");
	remove("imgui.ini");

	glfwSwapInterval(1);

	int counter = 0;
	float f = 0.0f;

	while (!glfwWindowShouldClose(GUI::window))
	{
		// Poll and handle events
		glfwPollEvents();

		// Start the Dear ImGui frame
		ImGui_ImplOpenGL3_NewFrame();
		ImGui_ImplGlfw_NewFrame();
		ImGui::NewFrame();

		// Create a simple user interface
		{
			if (ImGui::BeginMainMenuBar())
			{
				if (ImGui::BeginMenu("File"))
				{
					if (ImGui::MenuItem("Open", "Ctrl+O")) { /* Do stuff */ }
					if (ImGui::MenuItem("Save", "Ctrl+S")) { /* Do stuff */ }
					if (ImGui::MenuItem("Close", "Ctrl+W")) { /* Do stuff */ }
					ImGui::EndMenu();
				}
				if (ImGui::BeginMenu("Edit"))
				{
					if (ImGui::MenuItem("Undo", "Ctrl+Z")) { /* Do stuff */ }
					if (ImGui::MenuItem("Redo", "Ctrl+Y")) { /* Do stuff */ }
					ImGui::EndMenu();
				}
				ImGui::EndMainMenuBar();
			}
			ImGui::SetNextWindowSize(ImVec2(1280, 720));
			ImGui::SetNextWindowPos(ImVec2(0, 20));
			ImGui::Begin("Table with Selectable Rows", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse);
			if (ImGui::Button("Open Popup"))
				ImGui::OpenPopup("MyPopup");

			ImGui::SetNextWindowSize(ImVec2(300, 200));
			ImGui::SetNextWindowPos(ImVec2(640 - 150, 360 - 100));
			if (ImGui::BeginPopupModal("MyPopup", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove))
			{
				ImGui::Text("Hello, world!");
				if (ImGui::Button("Close"))
					ImGui::CloseCurrentPopup();
				ImGui::EndPopup();
			}

			if (ImGui::BeginTable("table1", 3))
			{
				ImGui::TableSetupColumn("Column 1");
				ImGui::TableSetupColumn("Column 2");
				ImGui::TableSetupColumn("Column 3");
				ImGui::TableHeadersRow();

				static bool selected[5] = { false, false, false, false, false };
				for (int row = 0; row < 5; row++)
				{
					ImGui::TableNextRow();
					for (int column = 0; column < 3; column++)
					{
						ImGui::TableSetColumnIndex(column);
						if (column == 0)
						{
							/*char label[32];
							sprintf(label, "Row %d", row);*/
							std::stringstream ss;
							ss << "label" << row << std::endl;
							if (ImGui::Selectable(ss.str().c_str(), &selected[row], ImGuiSelectableFlags_SpanAllColumns))
							{
								std::cout << "row " << row << " column " << column << " clickedy\n";
							}
						}
						else
						{
							ImGui::Text("Cell %d,%d", row, column);
						}
					}
				}
				ImGui::EndTable();
				ImGui::Text("This is some useful text.");
				ImGui::SliderFloat("float", &f, 0.0f, 1.0f);
				if (ImGui::Button("Button"))
					counter++;
				ImGui::SameLine();
				ImGui::Text("counter = %d", counter);
				if (ImGui::Button("Open File Dialog"))
					ImGuiFileDialog::Instance()->OpenDialog("ChooseFileDlgKey", "Choose File", ".cpp,.h,.hpp", ".");

				// display
				if (ImGuiFileDialog::Instance()->Display("ChooseFileDlgKey"))
				{
					// action if OK
					if (ImGuiFileDialog::Instance()->IsOk())
					{
						std::string filePathName = ImGuiFileDialog::Instance()->GetFilePathName();
						std::string filePath = ImGuiFileDialog::Instance()->GetCurrentPath();
						// action
					}

					// close
					ImGuiFileDialog::Instance()->Close();
				}
			}

			ImGui::End();
		}

		// ImGuiIO& io = ImGui::GetIO();

		// Rendering
		glClear(GL_COLOR_BUFFER_BIT);
		ImGui::Render();
		ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
		glfwSwapBuffers(GUI::window);
	}

	return 0;
}