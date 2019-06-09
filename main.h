#include <string>
#include <pcap.h>


#ifndef UNTITLED_MAIN_H
#define UNTITLED_MAIN_H

std::string input_file;
std::string output_file;

struct bpf_program filterprog;
pcap_t * pcap;

#endif //UNTITLED_MAIN_H
