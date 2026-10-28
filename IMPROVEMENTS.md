# RustyDolphin engineering improvements

This document explains the hardening and redesign work performed in August 2026. It is intended to be read as a code-review and learning guide, not merely as a changelog.

## Goals

The pass kept the existing ImGui interface and packet-analysis features, while improving:

- correctness on malformed or truncated network input;
- ownership and deterministic cleanup;
- communication between capture and UI threads;
- Windows API usage;
- runtime dependency behavior;
- failure handling and diagnosability.

## 1. Runtime dependency mismatch

### Symptom

The program first failed because `wpcap.dll` was missing. After Npcap was installed, Windows reported that `PacketGetInfo` could not be found.

### Root cause

Npcap supplies a matched pair of DLLs: `wpcap.dll` and `Packet.dll`. The repository's Debug output contained `Packet.dll` 1.72, while the installed Npcap was 1.88. Windows searches the executable directory before Npcap's directory, so it combined incompatible versions.

### Change

The stale, checked-in Debug `Packet.dll` was removed. RustyDolphin now uses the matching DLL pair installed by Npcap.

### Lesson

An import library (`.lib`) is a build dependency; a DLL is a runtime dependency. Native DLLs that call into each other must normally come from the same release. Avoid committing generated output directories and arbitrary copies of system runtimes. If redistribution is desired, check Npcap's license before packaging its binaries.

## 2. Standard program entry point

`void main()` is not standard C++. It was changed to `int main()`, and `WinMain` now returns the result of `main`. This removes compiler warning C4326 and gives the operating system a well-defined exit status.

## 3. Packet parsing now has a hard memory boundary

### Original design

Methods such as `parseChar`, `parseShort`, `parseIPV4`, and `parse(size)` advanced a cursor and read memory without checking `pcap_pkthdr::caplen`. A truncated frame could therefore read beyond the allocated packet buffer. Network input must always be treated as untrusted, even when it comes from a capture file.

### Change

`Packet::ensureAvailable` validates every read. It uses this overflow-safe condition:

```cpp
if (size > m_len || m_pos > m_len - size)
```

The subtraction is performed only after proving `size <= m_len`, avoiding unsigned underflow. Invalid reads throw `std::out_of_range`. The capture loop catches parsing exceptions, logs the reason, skips that frame, and continues processing later frames.

Ethernet, IPv4, and IPv6 dispatch also validates that fixed header offsets exist before reading protocol fields.

### Lesson

Bounds checks belong at the lowest reusable read primitive. Checking only once in a caller is easy to forget when new protocol classes are added.

## 4. IPv4 header decoding was corrected

An IPv4 packet starts with one byte containing two nibbles:

```text
high nibble: version
low nibble: Internet Header Length (32-bit words)
```

The old code multiplied the entire byte by four. A normal `0x45` byte therefore became a 276-byte header instead of 20 bytes.

The corrected calculation is:

```cpp
version = versionAndLength >> 4;
headerLength = (versionAndLength & 0x0F) * 4;
```

The parser also rejects a version other than 4 and an IPv4 header smaller than 20 bytes.

## 5. IPv6 version, traffic class, and flow label decoding

The first IPv6 word is now decoded using its protocol-defined bit ranges:

- version: bits 31-28;
- traffic class: bits 27-20;
- flow label: bits 19-0.

The old traffic-class shift and mask did not select the correct bits. The parser now also rejects a version other than 6.

## 6. Release-only infinite loop removed

When an unknown IPv4 option appeared, code that consumed the remaining option bytes was inside `#ifdef _DEBUG`. In Debug the parser advanced; in Release it repeatedly inspected the same byte forever.

Logging remains conditional, but cursor advancement is now unconditional. Debug macros should affect observability, not program correctness.

## 7. Packet ownership uses RAII

### Original design

Captured packets were stored as `Packet*`. Three UI paths manually looped over the vector and called `delete`. That design makes leaks, double deletion, and missed cleanup likely as control flow grows.

### Change

The collection is now:

```cpp
std::vector<std::unique_ptr<Packet>>
```

`Data::addPacket` accepts ownership, and `Data::clearPackets` clears packets, count, and selection as one operation. Destruction happens automatically.

Protocol-option base classes received virtual destructors. IPv4, IPv6, and TCP destructors release their currently raw-owned option objects. This is an intermediate improvement; converting option vectors to `std::unique_ptr` would be the ideal follow-up.

### Lesson

Use raw pointers for non-owning observation. Express single ownership with `std::unique_ptr`; the type system then documents and enforces the lifetime rule.

## 8. Thread communication was made explicit

### Problems

The capture thread and UI thread read and wrote plain `bool` and `long` globals concurrently. In C++, that is a data race and therefore undefined behavior; it is not made safe because reads and writes happen to fit in one CPU instruction.

The adapter counters had the same problem. The UI also accessed the packet vector before acquiring its mutex.

### Changes

- stop flags, capture count, and geo-worker state use atomics;
- adapter counters use `std::atomic_int`;
- packet insertion updates the vector and visible count together;
- UI iteration locks before inspecting the vector;
- expanded-packet rendering validates selection while holding the same lock;
- geo-location readers lock before inspecting their vector;
- the logger serializes writes from worker threads.

Atomics are appropriate for independent scalar state. A mutex is appropriate when multiple values or a container must remain consistent as a group.

## 9. Threads use value semantics

Adapter workers used `new std::thread`, stored raw pointers, and needed an explicit join/delete loop. They are now stored as `std::jthread` values. Clearing or destroying the vector joins them automatically.

This is RAII applied to concurrency: if a scope owns a running thread, its destructor should establish a safe end-of-scope state.

## 10. Capture-loop termination and malformed frames

The original first-packet loop ignored every non-positive `pcap_next_ex` result. That meant EOF (`-2`) and errors (`-1`) could cause an infinite loop on an empty or invalid capture.

The new loop distinguishes:

- `1`: a packet is available;
- `0`: live-capture timeout, so try again unless stopping;
- `-2`: offline EOF, mark loading complete;
- other negative values: stop safely.

A malformed first frame is skipped rather than ending the whole capture.

## 11. Adapter and UI bounds

- `Capture::getDev` now rejects `index >= deviceCount`; the old `>` allowed one-past-the-end.
- IP lookup is not attempted when no adapter was selected.
- Down-arrow selection is capped at `packetCount - 1`, not `packetCount`.
- Expanded rendering checks that the selected index still exists.

One-past-the-end values are useful iterators, but never valid element indexes.

## 12. Capture-file replay and handle lifetime

Starting an offline capture again previously reused a pcap handle already positioned at EOF, so it immediately ended. RustyDolphin now remembers the loaded path, closes the exhausted handle, reopens the file, and replays it from the beginning.

Loading another file closes the previous pcap handle after its capture thread has joined. Save now checks whether `pcap_dump_open` succeeded before writing.

## 13. Shutdown ordering

Cleanup was previously registered before subsystem initialization. If initialization failed halfway through, cleanup could call GUI and Windows teardown functions for objects that never initialized.

Cleanup registration now happens only after successful initialization. Shutdown signals and joins worker threads before destroying resources those threads may use. The selected pcap handle is closed and nulled to prevent accidental reuse.

## 14. Windows process discovery uses a structured API

### Original design

The program ran `tasklist`, searched for English words such as `Console` and `Services`, walked backward through the output, and reconstructed PIDs with floating-point `pow`. This was dependent on output layout and OS language, and several index operations could throw.

### Change

It now uses `CreateToolhelp32Snapshot`, `Process32First`, and `Process32Next`. Executable names are converted from UTF-16 to UTF-8 through one helper.

Structured APIs are preferable to parsing human-oriented command output. They provide explicit types, stable contracts, and error codes.

## 15. Windows resource and buffer fixes

- process handles are closed even when name lookup fails;
- TCP/UDP table refresh checks for allocation/API failure before dereferencing;
- stale port-to-PID mappings are cleared before refresh;
- `GetModuleBaseName` receives a character count instead of a byte count;
- the ICMP send buffer uses the string length, not `sizeof(pointer)`;
- the ICMP reply size uses the payload length, not `sizeof(pointer)`;
- the ICMP payload and handle are released safely.

## 16. GUI resource handling

Image loads are checked before use. The earth image's CPU pixels are freed after uploading them to OpenGL, and the OpenGL texture is deleted during shutdown. The window icon is only installed when decoding succeeds.

CPU image memory and GPU texture memory are separate resources; uploading does not automatically free either one.

## 17. Filter validation

Inputs without `=`, with multiple `=` characters, with an empty key, or with an empty value now produce a user-facing validation error instead of passing `npos` values into `substr` and potentially throwing.

## 18. ICMPv6 fallback behavior

Several resolver functions could reach the end of a non-void function, which is undefined behavior. Unknown codes now fall back to their numeric value. Unknown message types no longer insert an empty value into the global lookup map.

## Verification

The project is verified with Visual Studio MSBuild using both relevant x64 configurations:

```powershell
msbuild RustyDolphin.sln /m /p:Configuration=Debug /p:Platform=x64
msbuild RustyDolphin.sln /m /p:Configuration=Release /p:Platform=x64
```

Npcap must be installed. Do not place a different `Packet.dll` beside the executable.

## Recommended next redesigns

These are intentionally listed rather than rushed into one large change:

1. Replace the global `Data` service locator with an `ApplicationState` instance owned by `App`.
2. Give capture sessions a class that owns `pcap_t` through a custom `unique_ptr` deleter.
3. Convert all protocol-option vectors to `std::unique_ptr` and remove their manual destructors.
4. Replace exception-based parse failure with `std::expected<T, ParseError>` when the chosen compiler/library supports it consistently.
5. Separate packet decoding from rendering. A parser should produce immutable packet models; ImGui should only consume them.
6. Add unit tests built from small byte arrays for truncated Ethernet, IPv4 IHL, IPv6 fields, TCP/UDP lengths, and filter grammar.
7. Replace shelling out to `curl` with an in-process HTTP client and add timeouts, URL encoding, response validation, and cancellation.
8. Replace `atexit` with a top-level RAII application object so partial initialization also cleans up safely.
9. Stop checking generated `x64`, `.vs`, DLL, LIB, EXP, and runtime files into source control; publish versioned release artifacts separately.
10. Add CI that builds Debug and Release with warnings treated as errors for project sources.

The most valuable next step is automated parser testing. Packet decoders are deterministic functions over bytes, so they are unusually well suited to table-driven tests and fuzzing.

### Implementation status (August 2026 follow-up)

The follow-up implements the parts that can be introduced without rewriting the entire GUI in one unsafe change:

1. **Application state:** complete. `App` owns one `ApplicationState`. Capture, renderer, and geolocation operations receive it explicitly by reference; packet models no longer inspect session state. The former `Data` service locator is gone. Shared protocol-name tables remain in the accurately named `ProtocolCatalog` because they are immutable application-independent reference data.
2. **Capture ownership:** complete. `PcapHandle` is a `std::unique_ptr<pcap_t, PcapCloser>`. Opening a live or file capture returns ownership, reassignment closes the previous session, and explicit `pcap_close` calls were removed.
3. **Protocol-option ownership:** complete. IPv4, IPv6, and TCP option collections hold `std::unique_ptr`; manual destructor loops were removed.
4. **Structured parse failure:** complete for the new core decoder. It uses C++23 `std::expected<T, ParseError>`, including the byte offset and a readable reason. The legacy packet classes still throw while they are gradually replaced by this boundary.
5. **Decode/render separation:** complete at the dependency boundary. Packet headers contain no ImGui, GLFW, or `Renderer` dependency and expose no `render` methods. `App` gives packet models to a state-aware `Renderer`, which centrally dispatches the concrete protocol view. The pure `Core/PacketDecoder` remains the preferred immutable decoding API for new protocol work.
6. **Unit tests:** complete for the recommended first matrix: truncated Ethernet, IPv4 version/IHL, IPv6 bit fields, TCP header length/NS, UDP length, and filter grammar. CTest runs these without Npcap or a GUI.
7. **In-process HTTP:** complete. WinHTTP replaced `_popen`/`curl.exe`; it supplies KeyCDN's required user agent, URL-encodes the host parameter, enforces connection/read timeouts, validates HTTP status, validates JSON, and checks cancellation between reads.
8. **Top-level cleanup:** `atexit` was removed. A stack-owned lifetime object calls shutdown during normal return and C++ exception unwinding. Some older subsystem initialization paths still call `exit`; converting those to typed initialization errors remains necessary for perfect partial-initialization cleanup.
9. **Generated artifacts:** `.vs`, `x64`, and CMake build directories are ignored. Previously tracked IDE/build/runtime output was removed from the Git index while preserved on the developer machine. Third-party import libraries under `deps` remain source dependencies and are intentionally tracked.
10. **CI:** GitHub Actions configures CMake, builds Debug and Release, and runs CTest. Project sources compile at `/W4 /WX`; vendored headers/sources are treated as external because their warnings are not controlled by this project.

The state is passed explicitly—there is no global `getState()` accessor masquerading as dependency injection. Likewise, model-to-view dependencies were removed rather than merely hidden behind another virtual method.

## 31. Completed state and rendering migrations

`ApplicationState` groups mutable capture, filter, selection, modal, worker, and geolocation state. Its owner is `App`; collaborators receive a reference only when their operation needs it. This makes ownership visible in function signatures and permits isolated instances in future tests.

`ProtocolCatalog` contains only shared lookup tables such as DSCP, ICMP, ARP, and TCP flag names plus the pure map projection helper. These values describe protocols rather than a running application, so sharing them does not create mutable session coupling.

Rendering now flows in one direction:

```text
App owns ApplicationState
  -> capture/SDK update explicitly supplied state
  -> packet decoders produce packet models
  -> App passes models and state to Renderer
  -> Renderer alone calls ImGui
```

Previously every packet subclass included `Renderer.h` and implemented virtual `render()` functions. That made the model layer depend on the GUI and used virtual calls only to select an overloaded renderer. Central renderer dispatch removes that inverted dependency. Packet models can now be constructed, parsed, serialized, and tested without including ImGui or GLFW.

## 28. CMake, presets, Make, and what they do

CMake is a build-system generator. `CMakeLists.txt` describes source files, include directories, libraries, compiler requirements, tests, and copied runtime assets once. A generator then creates native Visual Studio projects from that description.

A preset is a named bundle of CMake settings:

- `vs2022` and `vs2026` configure an x64 build tree in `build/`;
- `debug`/`release` and their `-2026` forms compile one configuration;
- matching test presets tell CTest which executable configuration to run.

The important distinction is:

```text
configure: CMake reads CMakeLists.txt and generates build files
build:     Visual C++ compiles sources and links RustyDolphin.exe
test:      CTest launches RustyDolphinTests and reports pass/fail
run:       Windows launches the GUI executable
```

`build.ps1` is the beginner-friendly front end. It locates Visual Studio's bundled CMake when `cmake.exe` is not on `PATH`, chooses the installed Visual Studio generation, and runs those phases. The `Makefile` is only a convenience for environments where `make` already exists; CMake does not require Make when it generates Visual Studio projects.

The application target links Npcap, GLFW, OpenGL, WinSock, IP Helper, and WinHTTP. The test target links only the pure core decoder and filter parser. Keeping that test dependency graph small is why malformed input can be checked quickly without opening a window or requiring capture privileges.

## 29. Parser core and tests

`PacketDecoder` accepts `std::span<const std::uint8_t>`, which is a non-owning byte view carrying its length. Every decoder checks the fixed header, validates protocol-specific lengths, then returns either a value or `ParseError`. It never reads a byte before proving that byte exists.

`FilterParser` similarly returns either a complete normalized map or one error string. UI state updates happen only after parsing finishes, so an invalid expression cannot leave half of the previous filter mixed with half of the new one.

The tests use tiny arrays rather than captured network traffic. Each array documents exactly which bytes matter, is deterministic, and runs in milliseconds. New decoder bugs should first receive a failing byte-array test, followed by the fix.

## 30. WinHTTP geolocation

Shelling out created a child process, depended on an external executable, made quoting/URL encoding fragile, and prevented direct ownership of the request. The WinHTTP implementation owns session, connection, and request handles with `unique_ptr` custom deleters. All exit paths therefore close native handles.

The KeyCDN request now uses the identifiable user agent `keycdn-tools:https://github.com/SuperTapood/RustyDolphin`. The address is encoded as a query parameter, HTTP status must be 200, and the existing JSON anti-corruption layer converts the response to `GeoLocation`. Cancellation is cooperative between WinHTTP reads; the five-second receive timeout bounds a read already inside the operating system.

## 19. Geolocation crash: missing API fields

### Symptom

Opening geolocation terminated the application. The capture log did not contain a useful error because the exception occurred on the UI thread.

### Root cause

The KeyCDN response currently contains fields such as `ip`, `isp`, `latitude`, `longitude`, and `timezone`, but it no longer always contains `rdns`. The worker stored the entire third-party JSON document. Later, the renderer used:

```cpp
data.at("rdns")
```

`json::at` throws when a key is absent. Nothing caught that exception on the render thread, so the process terminated. Other schema changes, null coordinates, numeric strings, or unsuccessful API responses could fail similarly.

### Redesign

A new `GeoLocation` domain model is the only data passed to the UI. The network layer validates the response and converts it once:

- text fields receive an `Unknown` fallback;
- coordinates use `std::optional<double>`;
- unsuccessful or structurally invalid responses are rejected;
- JSON parsing and network failures are caught in the worker and logged;
- the renderer no longer knows the API's JSON schema.

### Lesson

Do not let an external service's wire representation become your application's internal state. Parse at the boundary into a small validated type. This is an example of an anti-corruption layer: upstream changes are absorbed in one place rather than leaking through the UI.

## 20. Cancellable and bounded geolocation work

Geolocation now uses `std::jthread`'s `std::stop_token`. Starting or closing a trace requests cancellation and joins the old worker safely. The old global termination flag remains for application-wide shutdown, but ordinary feature cancellation uses the thread's own token.

The HTTP command now has a three-second connection timeout and five-second total timeout. A failed `_popen` throws into the worker's error boundary rather than calling `exit` and terminating the entire application.

The old modal refused to close while work was in progress. It now presents `Cancel` during work and `Close` afterward. Cancellation can still wait briefly for a currently running `curl` process because `_popen` does not expose a cancellable process handle. Replacing this with an in-process HTTP client remains the ideal design.

## 21. Geolocation UI and map redesign

The original modal rendered a 500-pixel table and a 794-pixel map consecutively inside a 720-pixel window. The views are now separate tabs.

The map scales to the available content area while preserving aspect ratio. Marker coordinates use the same scale and the image's actual screen origin. Missing coordinates are skipped. Latitude is clamped to Web Mercator's valid limit (approximately ±85.0511 degrees), and longitude is clamped to ±180 degrees, preventing infinities and invalid draw coordinates.

Third-party strings are rendered with `ImGui::TextUnformatted` instead of being interpreted as printf-style format strings.

## 22. Fragment-aware IPv4 dispatch

Only an IPv4 fragment with offset zero contains the transport header. The old dispatcher treated every fragment as TCP, UDP, ICMP, or IGMP and interpreted arbitrary fragment payload as a header. Non-initial fragments are now decoded only through the IPv4 layer.

This also explains some previous `Skipping malformed packet` log entries: strict bounds checking exposed unsupported fragmentation behavior rather than causing silent out-of-bounds reads.

## 23. Correct TCP flag extraction

The TCP NS flag is stored in the low bit of the data-offset byte, while the other eight flags occupy the next byte. The former mask `0x1111` was not meaningful for an 8-bit value. The parser now shifts the NS bit into bit 8 and combines it with the unsigned flags byte.

## 24. Per-packet expansion state

The map controlling expanded protocol sections was static, so expanding a section on one packet affected every packet. It is now an instance member. UI state belongs to the packet view being inspected, not to the packet class as a whole.

## 25. Large-capture rendering optimization

The packet table previously submitted every filtered row to ImGui every frame. It now builds the filtered pointer list and uses `ImGuiListClipper` to render only visible rows.

Packet capture also no longer waits while the UI renders the entire table. The UI briefly locks the owning vector, copies non-owning packet pointers, releases the lock, then filters and renders the stable heap objects. This is safe under the current lifecycle because the worker only appends; clearing is performed by the UI after the capture thread is joined.

The remaining O(n) filtering scan can later be eliminated with a cached filtered-index list rebuilt only when a packet arrives or the filter changes.

## 26. Filter clear behavior

The Clear button previously erased only the text box, leaving the already parsed filter active. It now reprocesses the empty filter immediately, so displayed results match the visible control state.

## Updated verification notes

The geolocation fix was checked against the current KeyCDN response for a public test address, including its absent `rdns` field. Both Debug and Release builds remain part of final verification. The Debug-only LNK4098 warning comes from incompatible runtime choices in prebuilt third-party libraries and should be resolved by rebuilding dependencies consistently, not suppressed with `/NODEFAULTLIB`.

## 27. Why every trace reported “no address could be reached”

Two independent assumptions made the first crash fix appear unable to locate anything.

First, `getAlienAddr` decided which endpoint was remote by comparing the packet source with one adapter IP string. If adapter discovery produced an empty value, selected a different address, or the capture involved another local interface, an outbound packet selected its private source (for example `192.168.x.x`) instead of its public destination. Public geolocation services intentionally provide little or no location data for private addresses.

Endpoint selection now classifies both IPv4 addresses by scope. When exactly one is public, that address is selected. The classification covers private, loopback, link-local, carrier-grade NAT, multicast/reserved, and benchmark ranges. The adapter address is only a secondary hint.

Second, the feature assumed a destination was unreachable when routers did not return ICMP TTL-expired messages. Corporate firewalls, consumer routers, VPNs, and providers commonly filter those replies even while ordinary traffic to the destination works perfectly.

Traceroute is now optional enrichment:

- intermediate replies are collected when available;
- duplicate hop addresses are removed;
- probing is capped at 30 hops with a bounded timeout;
- the destination address is always appended as a geolocation fallback;
- the UI explains when intermediate routers blocked discovery;
- an empty lookup is described as unavailable public geolocation data, not an unreachable host.

The `IcmpSendEcho` reply buffer was also enlarged according to the Windows API contract: reply header + request payload + eight bytes for ICMP error information. The undersized buffer could prevent useful TTL-expired replies from being returned.

### Lesson

Reachability, route observability, and geolocation availability are three different facts. A robust UI must not infer one from the absence of another.
