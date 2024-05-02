DEBUG=0
CXXFLAGS=-std=c++17 -Wall -Iexternal/Catch2/single_include -I../include
SOURCES=main.cpp aes_tests.cpp base64_tests.cpp crc_tests.cpp fnv1_tests.cpp md5_tests.cpp sha1_tests.cpp sha2_tests.cpp utf8_tests.cpp uuid_tests.cpp
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
	-del /f /q "$(EXECUTABLE).exe" $(OBJECTS) *.gcda *.gcno
else
	$(RM) $(EXECUTABLE) $(OBJECTS) $(EXECUTABLE).exe $(DEPENDENCIES) *.gcda *.gcno
endif