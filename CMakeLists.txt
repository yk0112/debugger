cmake_minimum_required (VERSION 3.0)
project (debugger)

add_compile_options(-std=c++14)

include_directories(modules/libelfin modules/linenoise include)
add_executable(debugger src/main.cpp ./modules/linenoise/linenoise.c)

add_executable(test examples/test.cpp)
set_target_properties(test
                      PROPERTIES COMPILE_FLAGS "-g -gdwarf-4 -O0")       
                      
add_executable(test2 examples/test2.cpp)
set_target_properties(test2
                      PROPERTIES COMPILE_FLAGS "-g -gdwarf-4 -O0")  

add_executable(test3 examples/test3.cpp)
set_target_properties(test3
                      PROPERTIES COMPILE_FLAGS "-g -gdwarf-2 -O0")                      

add_custom_target(
   libelfin
   COMMAND make
   WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/modules/libelfin
)
target_link_libraries(debugger
                      ${PROJECT_SOURCE_DIR}/modules/libelfin/dwarf/libdwarf++.so
                      ${PROJECT_SOURCE_DIR}/modules/libelfin/elf/libelf++.so)
add_dependencies(debugger libelfin)