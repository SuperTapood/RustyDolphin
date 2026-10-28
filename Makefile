.PHONY: configure build debug test clean run

configure:
	cmake --preset vs2022

build: configure
	cmake --build --preset release

debug: configure
	cmake --build --preset debug

test: debug
	ctest --preset debug

run: build
	./build/bin/Release/RustyDolphin.exe

clean:
	cmake -E remove_directory build
