MAKEFILE_PATH:=$(abspath $(lastword $(MAKEFILE_LIST)))
ROOT_DIR:=$(realpath $(dir $(MAKEFILE_PATH)))
debug=0
CXXFLAGS=-c -std=c++11 -Wall -O2 -I$(ROOT_DIR)/../include
LDFLAGS=-O2 -fprofile-arcs -ftest-coverage
SOURCES=$(ROOT_DIR)/main.cpp
BASE_NAMES=$(basename $(SOURCES))
OBJECTS=$(BASE_NAMES:=.o)
EXECUTABLE=test

all: $(EXECUTABLE)
ifeq ($(debug),1)
all: CXXFLAGS+=-DDEBUG -g
endif

$(EXECUTABLE): $(OBJECTS)
	$(CXX) $(OBJECTS) $(LDFLAGS) -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

.PHONY: clean
clean:
ifeq ($(OS),Windows_NT)
	-del /f /q "$(ROOT_DIR)\$(EXECUTABLE).exe" "$(ROOT_DIR)\*.o"
else
	$(RM) $(ROOT_DIR)/$(EXECUTABLE) $(ROOT_DIR)/*.o $(ROOT_DIR)/$(EXECUTABLE).exe
endif