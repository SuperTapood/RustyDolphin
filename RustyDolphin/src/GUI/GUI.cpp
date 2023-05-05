#include "GUI.h"
#include "ImageLoader.h"

GLFWwindow* GUI::window;

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
}

void GUI::release() {
	// Cleanup
	ImGui_ImplOpenGL3_Shutdown();
	ImGui_ImplGlfw_Shutdown();
	ImGui::DestroyContext();

	glfwTerminate();
}