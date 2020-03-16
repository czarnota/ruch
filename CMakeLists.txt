cmake_minimum_required(VERSION 3.1)

project(ruch)
file(GLOB ruch_sources *.c)
add_executable(ruch ${ruch_sources})
