cmake_minimum_required(VERSION 3.26)
project(elf)

set(CMAKE_CXX_STANDARD 17)

if(MSVC)
else ()
    add_compile_options("-nostdinc++" "-Wall" "-fno-exceptions" "-fno-rtti")
    message("Hello sailor")
endif ()

add_executable(elf main.cpp)
