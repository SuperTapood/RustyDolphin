#include "GUI.h"
#include "ImageLoader.h"
#include "../Base/Data.h"

GLFWwindow* GUI::window;
std::map<std::string, ImFont*> GUI::fonts;

void GUI::init() {
	if (!glfwInit())
		exit(-1);

	glfwWindowHint(GLFW_RESIZABLE, GLFW_FALSE);
	glfwWindowHint(GLFW_REFRESH_RATE, 1000);

	window = glfwCreateWindow(1280, 720, "RustyDolphin", NULL, NULL);
	if (!window)
	{
		glfwTerminate();
		exit(-1);
	}

	glfwMakeContextCurrent(window);

	GLFWimage images[1]{};
	images[0].pixels = stbi_load("deps/assets/icon.png", &images[0].width, &images[0].height, 0, 4); //rgba channels
	glfwSetWindowIcon(window, 1, images);
	stbi_image_free(images[0].pixels);

	// Initialize Dear ImGui
	IMGUI_CHECKVERSION();
	ImGui::CreateContext();

	// Set Dear ImGui style
	ImGui::StyleColorsDark();

	// Initialize Dear ImGui backends
	ImGui_ImplGlfw_InitForOpenGL(window, true);
	ImGui_ImplOpenGL3_Init("#version 150");

	//// Get the font atlas
	//ImGuiIO& io = ImGui::GetIO();
	//ImFontAtlas* atlas = io.Fonts;

	//// Clear the current fonts
	//atlas->Clear();

	//// Add a single font
	//atlas->AddFontDefault();

	//atlas->Flags |= ImFontAtlasFlags_NoPowerOfTwoHeight;

	//// Build the font atlas
	//atlas->Build();

	ImGuiIO& io = ImGui::GetIO();

	fonts.insert({ "title", io.Fonts->AddFontFromFileTTF("deps/fonts/arial.ttf", 60) });
	fonts.insert({ "quote", io.Fonts->AddFontFromFileTTF("deps/fonts/arial.ttf", 25) });
	fonts.insert({ "adapters", io.Fonts->AddFontFromFileTTF("deps/fonts/arial.ttf", 30) });
	fonts.insert({ "regular", io.Fonts->AddFontFromFileTTF("deps/fonts/arial.ttf", 16) });
	fonts.insert({ "hexView", io.Fonts->AddFontFromFileTTF("deps/fonts/consola.ttf", 20) });
	io.Fonts->Build();

	glfwSwapInterval(0);

	ImGuiStyle& style = ImGui::GetStyle();
	style.Colors[ImGuiCol_Button] = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
	style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.5f, 0.5f, 0.5f, 0.5f);
}

void GUI::release() {
	// Cleanup
	ImGui_ImplOpenGL3_Shutdown();
	ImGui_ImplGlfw_Shutdown();
	ImGui::DestroyContext();

	glfwTerminate();
}

void GUI::pushFont(std::string name) {
	ImGui::PushFont(fonts.at(name));
}

void GUI::popFont() {
	ImGui::PopFont();
}

void GUI::centerText(const char* text) {
	auto windowWidth = ImGui::GetWindowSize().x;
	auto textWidth = ImGui::CalcTextSize(text).x;
	ImGui::SetCursorPosX((windowWidth - textWidth) * 0.5f);
	ImGui::Text(text);
}

bool GUI::centerButton(const char* text) {
	auto windowWidth = ImGui::GetWindowSize().x;
	auto textWidth = ImGui::CalcTextSize(text).x;
	ImGui::SetCursorPosX((windowWidth - textWidth) * 0.5f);
	return ImGui::Button(text);
}

inline void GUI::startFrame() {
	// Poll and handle events
	glfwPollEvents();

	// Start the Dear ImGui frame
	ImGui_ImplOpenGL3_NewFrame();
	ImGui_ImplGlfw_NewFrame();
	ImGui::NewFrame();
}

inline void GUI::endFrame() {
	// Rendering
	GUI::popFont();
	glClear(GL_COLOR_BUFFER_BIT);
	ImGui::Render();
	ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
	glfwSwapBuffers(GUI::window);
}

void GUI::handleStop() {
	pushFont("adapters");
	ImGui::OpenPopup("StopCapture");

	ImGui::SetNextWindowSize(ImVec2(600, 500));
	ImGui::SetNextWindowPos(ImVec2(640 - 300, 360 - 250));
	if (ImGui::BeginPopupModal("StopCapture", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar))
	{
		centerText("Are you sure you want stop the current capture?");
		ImGui::SetCursorPosY(350);
		if (centerButton("Yes")) {
			Data::doneCapturing = true;
			Data::showStop = false;
		}
		ImGui::SetCursorPosY(430);
		if (centerButton("No")) {
			Data::showStop = false;
		}
		ImGui::EndPopup();
	}
	popFont();
}

void GUI::handleStart() {
	pushFont("adapters");
	ImGui::OpenPopup("StartCapture");

	ImGui::SetNextWindowSize(ImVec2(600, 500));
	ImGui::SetNextWindowPos(ImVec2(640 - 300, 360 - 250));
	if (ImGui::BeginPopupModal("StartCapture", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar))
	{
		GUI::centerText("You have an ongoing capture.");
		GUI::centerText("do you want to start another one?");
		GUI::centerText("(the current one will be reset)");
		ImGui::SetCursorPosY(350);
		if (centerButton("Yes")) {
			Data::doneCapturing = true;
			Data::selected = -1;
			Data::showStart = false;
			Data::captureThread.join();
			Data::captured.clear();
			Data::capIdx = 0;
			Data::doneCapturing = false;
			Data::captureThread = std::thread(Capture::capturePackets);
		}
		ImGui::SetCursorPosY(430);
		if (centerButton("No")) {
			Data::showStart = false;
		}
		ImGui::EndPopup();
	}
	popFont();
}

void GUI::handleStartFile() {
	pushFont("adapters");
	ImGui::OpenPopup("StartCapture");

	ImGui::SetNextWindowSize(ImVec2(600, 500));
	ImGui::SetNextWindowPos(ImVec2(640 - 300, 360 - 250));
	if (ImGui::BeginPopupModal("StartCapture", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar))
	{
		centerText("Your current capture is from a file.");
		centerText("file captures cannot be re-started.");
		centerText("would you like to reset the currently captured packets?");
		ImGui::SetCursorPosY(350);
		if (centerButton("Yes")) {
			Data::doneCapturing = true;
			Data::selected = -1;
			Data::showStart = false;
			Data::captureThread.join();
			Data::captured.clear();
			Data::capIdx = 0;
			Data::doneCapturing = false;
			Data::captureThread = std::thread(Capture::capturePackets);
		}
		ImGui::SetCursorPosY(430);
		if (centerButton("No")) {
			Data::showStart = false;
		}
		ImGui::EndPopup();
	}
	popFont();
}


constexpr auto columns = 7;


void GUI::render() {
	while (!glfwWindowShouldClose(GUI::window))
	{
		startFrame();

		GUI::pushFont("regular");

		ImGui::SetNextWindowPos(ImVec2(0, 20));
		ImGui::SetNextWindowSize(ImVec2(1280, 360));
		ImGui::Begin("Packet Table Window", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

		if (ImGui::BeginMainMenuBar()) {
			if (ImGui::BeginMenu("File")) {
				if (ImGui::MenuItem("Load")) {
					// handle load
				}
				if (ImGui::MenuItem("Save")) {
					// handle save
				}
				ImGui::EndMenu();
			}
			if (ImGui::BeginMenu("Capture")) {
				if (ImGui::MenuItem("Start")) {
					Data::showStart = true;
				}
				if (ImGui::MenuItem("Stop")) {
					Data::showStop = true;
				}
				ImGui::EndMenu();
			}
			ImGui::EndMainMenuBar();
		}

		if (Data::showStop) {
			handleStop();
		}
		else if (Data::showStart && !Data::fileAdapter) {
			handleStart();
		}
		else if (Data::showStart && Data::fileAdapter) {
			handleStartFile();
		}

		if (ImGui::BeginTable("Packet Table", columns))
		{
			ImGui::TableSetupColumn((("No. (" + std::to_string(Data::captured.size()) + ")").c_str()), ImGuiTableColumnFlags_WidthFixed, 80.0f);
			ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 90.0f);
			ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 200.0f);
			ImGui::TableSetupColumn("Destination", ImGuiTableColumnFlags_WidthFixed, 200.0f);
			ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthFixed, 100.0f);
			ImGui::TableSetupColumn("Length", ImGuiTableColumnFlags_WidthFixed, 50.0f);
			ImGui::TableSetupColumn("Info", ImGuiTableColumnFlags_WidthFixed, 560.0f);
			ImGui::TableHeadersRow();

			for (int row = 0; row < Data::capIdx - 1; row++)
			{

				ImGui::TableNextRow();

				{
					std::lock_guard<std::mutex> guard(Data::guard);
					Data::captured.at(row)->render();
				}

			}
			ImGui::EndTable();
		}
		ImGui::End();

		if (Data::selected != -1) {
			ImGui::SetNextWindowPos(ImVec2(0, 380));
			ImGui::SetNextWindowSize(ImVec2(640, 340));
			ImGui::Begin("Expanded Packet", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

			Data::captured.at(Data::selected)->renderExpanded();

			ImGui::End();

			ImGui::SetNextWindowPos(ImVec2(640, 380));
			ImGui::SetNextWindowSize(ImVec2(640, 340));
			ImGui::Begin("Packet Data View", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

			std::string str;

			GUI::pushFont("hexView");

			auto p = Data::captured.at(Data::selected);

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

		endFrame();
	}
}