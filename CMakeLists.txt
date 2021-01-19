cmake_minimum_required(VERSION 3.16)
project(report_ip_stat)

set(CMAKE_CXX_STANDARD 17)

add_executable(report_ip_stat main.cpp)
target_link_libraries(report_ip_stat -lpcap)