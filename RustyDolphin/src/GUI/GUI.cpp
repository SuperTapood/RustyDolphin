#include "GUI.h"
#include "ImageLoader.h"

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

	glfwSwapInterval(1);

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