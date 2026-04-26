# IRFPA Management System — Makefile
# =====================================
# Supports: Linux (native), macOS (native), Windows cross-compile (MinGW-w64)

CXX      = g++
CXXFLAGS = -std=c++17 -O2 -Wall -pthread
LDFLAGS  = -lsqlite3 -lpthread

UNAME := $(shell uname -s 2>/dev/null || echo Windows)

# ── Linux / macOS native build ────────────────────────────────────────────────
ifeq ($(UNAME),Darwin)
    BREW_SQLITE := $(shell brew --prefix sqlite 2>/dev/null)
    ifneq ($(BREW_SQLITE),)
        CXXFLAGS += -I$(BREW_SQLITE)/include
        LDFLAGS  += -L$(BREW_SQLITE)/lib
    endif
endif

all: server
	@echo ""
	@echo "  Build successful!"
	@echo "  Run : ./server"
	@echo "  Open: http://localhost:8080"

server: server.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

# ── Windows cross-compile from Linux (MinGW-w64) ─────────────────────────────
# Install: sudo apt-get install mingw-w64
# Usage  : make windows
MINGW     = x86_64-w64-mingw32-g++
WIN_FLAGS = -std=c++17 -O2 -Wall -static-libgcc -static-libstdc++
WIN_LIBS  = -lsqlite3 -lws2_32 -lpthread

windows: server_windows.cpp
	$(MINGW) $(WIN_FLAGS) -o server.exe $< $(WIN_LIBS)
	@echo ""
	@echo "  Windows build: server.exe"

# ── Windows native build instructions (on Windows machine) ────────────────────
#  MSYS2/MinGW-w64:
#    pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-sqlite3
#    g++ -std=c++17 -O2 -o server.exe server_windows.cpp -lsqlite3 -lws2_32 -lpthread
#
#  MSVC (Developer Command Prompt):
#    cl /std:c++17 /O2 /EHsc server_windows.cpp sqlite3.lib Ws2_32.lib /Fe:server.exe

clean:
	rm -f server server.exe irfpa_management.db

.PHONY: all windows clean
