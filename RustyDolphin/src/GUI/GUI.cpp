#include "GUI.h"
#include "ImageLoader.h"
#include <imgui_internal.h>
#include <iostream>

GLFWwindow* GUI::window;
std::map<std::string, ImFont*> GUI::fonts;
GLuint GUI::earthTex;

void GUI::init() {
	if (!glfwInit())
		exit(-1);

	// make the window non resizable
	glfwWindowHint(GLFW_RESIZABLE, GLFW_FALSE);

	window = glfwCreateWindow(1280, 720, "RustyDolphin", NULL, NULL);
	if (!window)
	{
		glfwTerminate();
		exit(-1);
	}

	glfwMakeContextCurrent(window);

	// load and set the icon image
	GLFWimage images[1]{};
	images[0].pixels = stbi_load("deps/assets/icon.png", &images[0].width, &images[0].height, nullptr, 4);
	glfwSetWindowIcon(window, 1, images);
	stbi_image_free(images[0].pixels);

	// ImGui initialization
	IMGUI_CHECKVERSION();
	ImGui::CreateContext();

	// dark mode fr fr im just like that og
	ImGui::StyleColorsDark();

	// init imgui for opengl
	ImGui_ImplGlfw_InitForOpenGL(window, true);
	ImGui_ImplOpenGL3_Init();

	ImGuiIO& io = ImGui::GetIO();

	// create le fonts
	fonts.insert({ "title", io.Fonts->AddFontFromFileTTF("deps/fonts/arial.ttf", 60) });
	fonts.insert({ "quote", io.Fonts->AddFontFromFileTTF("deps/fonts/arial.ttf", 25) });
	fonts.insert({ "adapters", io.Fonts->AddFontFromFileTTF("deps/fonts/arial.ttf", 30) });
	fonts.insert({ "regular", io.Fonts->AddFontFromFileTTF("deps/fonts/arial.ttf", 16) });
	fonts.insert({ "hexView", io.Fonts->AddFontFromFileTTF("deps/fonts/consola.ttf", 16) });

	// build the font altas
	io.Fonts->Build();

	glfwSwapInterval(1);
	
	// set button hovered colors (like on the table)
	ImGuiStyle& style = ImGui::GetStyle();
	style.Colors[ImGuiCol_Button] = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
	style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.5f, 0.5f, 0.5f, 0.5f);

	// load the earth image we need for the hopping map
	images[0].pixels = stbi_load("deps/assets/earth.jpeg", &images[0].width, &images[0].height, nullptr, 4);

	// bind the earth image to a texture we can render
	glGenTextures(1, &earthTex);
	glBindTexture(GL_TEXTURE_2D, earthTex);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
	glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, images[0].width, images[0].height, 0, GL_RGBA, GL_UNSIGNED_BYTE, images[0].pixels);
}

void GUI::release() {
	// clean up clean up
	ImGui_ImplOpenGL3_Shutdown();
	ImGui_ImplGlfw_Shutdown();
	ImGui::DestroyContext();

	// it always comes back
	glfwTerminate();
}

// two wrapper functions to make using fonts a little easier and consistent

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

void GUI::startFrame() {
	// handle events
	glfwPollEvents();

	// actually start the frame
	ImGui_ImplOpenGL3_NewFrame();
	ImGui_ImplGlfw_NewFrame();
	ImGui::NewFrame();
}

void GUI::endFrame() {
	// clear the frame
	glClear(GL_COLOR_BUFFER_BIT);
	// render the frame
	ImGui::Render();
	ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
	// swap le buffers
	glfwSwapBuffers(GUI::window);
}