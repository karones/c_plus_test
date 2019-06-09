cmake_minimum_required(VERSION 3.10)
project(filter)

set(CMAKE_CXX_STANDARD 14)
include(FindPCAP.cmake)

add_executable(filter main.cpp main.h)
target_link_libraries(filter ${PCAP_LIBRARY})
