DEBUG=0
CXXFLAGS=-std=c++17 -Wall -I../external/Catch2/single_include -I../include
LDFLAGS=-O2
SOURCES=main.cpp tests.cpp
BASE_NAMES=$(basename $(SOURCES))
OBJECTS=$(BASE_NAMES:=.o)
DEPENDENCIES=$(OBJECTS:.o=.d)
EXECUTABLE=test

all: $(EXECUTABLE)
ifeq ($(DEBUG),1)
all: CXXFLAGS+=-DDEBUG -g
else
all: CXXFLAGS+=-O3
all: LDFLAGS+=-O3
endif

$(EXECUTABLE): $(OBJECTS)
	$(CXX) $(OBJECTS) $(LDFLAGS) -o $@ -fprofile-arcs -ftest-coverage

-include $(DEPENDENCIES)

%.o: %.cpp
	$(CXX) -c $(CXXFLAGS) -MMD -MP $< -o $@ -fprofile-arcs -ftest-coverage

.PHONY: clean
clean:
ifeq ($(OS),Windows_NT)
	-del /f /q "$(EXECUTABLE).exe" $(OBJECTS)
else
	$(RM) $(EXECUTABLE) $(OBJECTS) $(EXECUTABLE).exe $(DEPENDENCIES) *.gcno
endif