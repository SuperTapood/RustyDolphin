# RustyDolphin

RustyDolphin is a Windows packet capture and analysis GUI built with C++20, Npcap, Dear ImGui, GLFW, and OpenGL.

## Requirements

- Windows 10 or 11
- Visual Studio 2022 or newer with Desktop development with C++
- [Npcap](https://npcap.com/) installed

Npcap's `wpcap.dll` and `Packet.dll` must come from the same installation. Do not copy an older `Packet.dll` beside the executable.

## Build

The easiest Windows command is:

```powershell
.\build.ps1 -Configuration Release -Test
```

The script finds the CMake bundled with Visual Studio, configures an x64 build,
builds the program, and runs the automated tests. Add `-Run` to launch it after
a successful build, or `-Clean` to discard the generated `build` directory first.

The equivalent raw CMake commands for Visual Studio 2022 are:

```powershell
cmake --preset vs2022
cmake --build --preset release
ctest --preset release
```

Visual Studio 2026 Insiders users can replace those preset names with `vs2026`,
`release-2026`, and `release-2026`. If you already have GNU Make, `make build`,
`make test`, and `make run` wrap the same operations; Make is optional on Windows.

Build output is placed under `build/bin/<Configuration>`. CMake copies the runtime
assets beside the executable. Npcap must still be installed because its matched
`wpcap.dll` and `Packet.dll` are loaded from the system Npcap directory.

You can still open `RustyDolphin/RustyDolphin.sln` and build x64 Debug or Release.
The CMake path is preferred because it also creates and runs the tests.

## Engineering notes

See [IMPROVEMENTS.md](IMPROVEMENTS.md) for a detailed explanation of the correctness, ownership, threading, parser, Windows API, and runtime-dependency improvements made to the project.

time spent making this nonsense in the best language ever made:

[![wakatime](https://wakatime.com/badge/user/8b4f0bdc-5133-4fba-98d4-d75498fa71f2/project/73bc670d-dbbf-467b-af69-086d56b73c16.svg)](https://wakatime.com/badge/user/8b4f0bdc-5133-4fba-98d4-d75498fa71f2/project/73bc670d-dbbf-467b-af69-086d56b73c16)
 
 [IP Location Finder by KeyCDN](https://tools.keycdn.com/geo)

General flow:

- Init everything and caches
- Fetch all adapters (maybe run some sort of check)
- Create render thread (main)
- Create a thread for each adapter to count packets and create rate
- Start rendering and present the rate
- Upon adapter selection, join threads and create another thread specifically for the chosen adapter
- Render the recieved packets which are picked up and analyzed by the thread
- Each packet is rendered according to the filtering
- On click, the packet will present in a small window
- In both of these cases, buttons will be presented to do further actions (such as geo track)
