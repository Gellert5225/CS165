# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/gellert/Documents/cs165/Project1

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/gellert/Documents/cs165/Project1

# Include any dependencies generated for this target.
include CMakeFiles/Project1.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/Project1.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/Project1.dir/flags.make

CMakeFiles/Project1.dir/src/main.cpp.o: CMakeFiles/Project1.dir/flags.make
CMakeFiles/Project1.dir/src/main.cpp.o: src/main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/gellert/Documents/cs165/Project1/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/Project1.dir/src/main.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/Project1.dir/src/main.cpp.o -c /home/gellert/Documents/cs165/Project1/src/main.cpp

CMakeFiles/Project1.dir/src/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/Project1.dir/src/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/gellert/Documents/cs165/Project1/src/main.cpp > CMakeFiles/Project1.dir/src/main.cpp.i

CMakeFiles/Project1.dir/src/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/Project1.dir/src/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/gellert/Documents/cs165/Project1/src/main.cpp -o CMakeFiles/Project1.dir/src/main.cpp.s

# Object files for target Project1
Project1_OBJECTS = \
"CMakeFiles/Project1.dir/src/main.cpp.o"

# External object files for target Project1
Project1_EXTERNAL_OBJECTS =

bin/Project1: CMakeFiles/Project1.dir/src/main.cpp.o
bin/Project1: CMakeFiles/Project1.dir/build.make
bin/Project1: /usr/local/ssl/lib/libssl.a
bin/Project1: /usr/local/ssl/lib/libcrypto.a
bin/Project1: CMakeFiles/Project1.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/gellert/Documents/cs165/Project1/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable bin/Project1"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/Project1.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/Project1.dir/build: bin/Project1

.PHONY : CMakeFiles/Project1.dir/build

CMakeFiles/Project1.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/Project1.dir/cmake_clean.cmake
.PHONY : CMakeFiles/Project1.dir/clean

CMakeFiles/Project1.dir/depend:
	cd /home/gellert/Documents/cs165/Project1 && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/gellert/Documents/cs165/Project1 /home/gellert/Documents/cs165/Project1 /home/gellert/Documents/cs165/Project1 /home/gellert/Documents/cs165/Project1 /home/gellert/Documents/cs165/Project1/CMakeFiles/Project1.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/Project1.dir/depend

