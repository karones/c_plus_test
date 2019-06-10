#include <string>
#include <pcap.h>
#include <vector>


#ifndef UNTITLED_MAIN_H
#define UNTITLED_MAIN_H
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6


std::string input_file;
std::string output_file;

struct bpf_program filterprog;
pcap_t * pcap;
struct ethernet_h{

u_char ether_dest_host[ETHER_ADDR_LEN]; //the destination host address
u_char ether_src_host[ETHER_ADDR_LEN]; //the source host address
u_short ether_type; //to check if its ip etc

};

bool vlan_flag = false;
std::vector<u_short> vlans;
#endif //UNTITLED_MAIN_H
