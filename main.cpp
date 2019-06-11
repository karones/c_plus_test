#include <iostream>
#include <getopt.h>
#include "main.h"
#include <arpa/inet.h>
#include <algorithm>

using namespace std;


void help() {
    cout << "filter [options] <input filename> <output filename> \n"
            " The utility should support any combination of following options\n"
            " -ip x.x.x.x – ip address of the packet, source or destination\n"
            " -sip x.x.x.x – source ip address of the packet should match\n"
            " -dip x.x.x.x – destination ip\n"
            " -tcp x – packet should have tcp type and that port, source or destination\n"
            " -stcp x - packet should have tcp type and that source port\n"
            " -dtcp x - packet should have tcp type and that destination port\n"
            " -udp x – packet should have udp type and that port, source or destination\n"
            " -sudp x – packet should have udp type and that source port\n"
            " -dudp x – packet should have udp type and that destination port\n"
            " -vlan x – packet should have at least one vlan tag with that id" << endl;
}


int main(int argc, char *argv[]) {
    int rez = 0;
    if (argc < 3)
    {
        help();
        exit(0);
    }
    //Для обработки входных параметров используем библиотеку getopt
    
    static struct option long_options[] = {
    {"ip",   required_argument, 0, 'i'},
    {"sip",  required_argument, 0, 's'},
    {"dip",  required_argument, 0, 'd'},
    {"tcp",  required_argument, 0, 't'},
    {"stcp", required_argument, 0, 'c'},
    {"dtcp", required_argument, 0, 'p'},
    {"udp",  required_argument, 0, 'u'},
    {"sudp", required_argument, 0, 'z'},
    {"dudp", required_argument, 0, 'x'},
    {"vlan", required_argument, 0, 'v'},
    {0, 0,                      0, 0}
    
};
    //флаг формирования первого элемента в фильтре
    bool first = true;
    string filter;
    while ((rez = getopt_long_only(argc, argv, "i:s:d:t:c:p:u:z:x:v:", long_options, NULL)) != -1) {
        
        //обработка ключей.
        switch (rez) {
        
        case 'i': //ip
            if (!first) {
                filter.append(" or host ");
                filter.append(optarg);
                first = false;
            } else {
                filter = "host ";
                filter.append(optarg);
            }
            break;
        case 's': //sip
            std::cout << optarg << std::endl;
            
            if (!first) {
                filter.append(" or src host ");
                filter.append(optarg);
                first = false;
            } else {
                
                filter = "src host ";
                filter.append(optarg);
            }
            break;
        case 'd': //dip
            std::cout << optarg << std::endl;
            
            if (!first) {
                filter.append(" or dst host ");
                filter.append(optarg);
                first = false;
            } else {
                
                filter = "dst host ";
                filter.append(optarg);
            }
            break;
            
        case 't': //tcp
            std::cout << optarg << std::endl;
            
            if (!first) {
                filter.append(" or tcp port ");
                filter.append(optarg);
                first = false;
            } else {
                
                filter = "tcp port ";
                filter.append(optarg);
            }
            break;
            
        case 'с': //stcp
            std::cout << optarg << std::endl;
            
            if (!first) {
                filter.append(" or tcp src port ");
                filter.append(optarg);
                first = false;
            } else {
                
                filter = "tcp src port ";
                filter.append(optarg);
            }
            break;
            
        case 'p': //dtcp
            std::cout << optarg << std::endl;
            
            if (!first) {
                filter.append(" or tcp dst port ");
                filter.append(optarg);
                first = false;
            } else {
                
                filter = "tcp dst port ";
                filter.append(optarg);
            }
            break;
            
        case 'u': //udp
            std::cout << optarg << std::endl;
            
            if (!first) {
                filter.append(" or udp port ");
                filter.append(optarg);
                first = false;
            } else {        //  cout<<e.String()<<endl;
                
                
                filter = "udp port ";
                filter.append(optarg);
            }
            break;
            
        case 'z': //sudp
            std::cout << optarg << std::endl;
            
            if (!first) {
                filter.append(" or udp src port ");
                filter.append(optarg);
                first = false;
            } else {
                
                filter = "udp src port ";
                filter.append(optarg);
            }
            break;
            
        case 'x': //dudp
            std::cout << optarg << std::endl;
            
            if (!first) {
                filter.append(" or udp dst port ");
                filter.append(optarg);
                first = false;
            } else {
                
                filter = "udp dst port ";
                filter.append(optarg);
            }
            break;

            //        case 'v': //vlan
            //            std::cout << optarg << std::endl;

            //            if (!first) {
            //                filter.append(" or vlan ");
            //                filter.append(optarg);
            //                first = false;
            //            } else {

            //                filter = "vlan ";
            //                filter.append(optarg);
            //            }
            //            break;
        case 'v': //vlan
            vlan_flag = true;
            //todo добавить проверку аргумента на корректность
            vlans.push_back( atoi(optarg));
            break;
            

            
            
        case 0:
            /* getopt_long() set a variable, just keep going */
            std::cout << optarg << std::endl;
            break;
            
        default:
            std::cout << "invalid" << std::endl;
            break;
            
            
        }
    }
    //получение имен файлов, которое передаются без ключей
    if (optind < argc) {
        if (optind < argc and (argc - optind) == 2) {
            input_file = argv[optind++];
            output_file = argv[optind++];
        }
    }
    
    if (input_file.empty() or output_file.empty()) {
        if (input_file.empty())
            cout << "Не корректно введен Input file" << endl;
        if (output_file.empty())
            cout << "Не корректно введен Output file" << endl;
        help();
        exit(-1);
    }
    
    char errbuff[PCAP_ERRBUF_SIZE];
    //читаем файл с данными
    try {
        pcap = pcap_open_offline(input_file.c_str(), errbuff);
        if (pcap == NULL)
        {
            cout << "error to open input file\n" << endl;
            help();
            exit(-1);
        }
    }
    catch (...) {
        cout << errbuff << endl;
        exit(-1);
    }
    
    
    struct pcap_pkthdr *header;
    //формирование фильтров
    int res = pcap_compile(pcap, &filterprog, filter.c_str(), 0,
                           PCAP_NETMASK_UNKNOWN);
    
    if (res !=0){
        cout << "creating filter make error "<<endl;
        help();
        exit(-2);
        
    }
    const u_char *data;
    
    res = pcap_setfilter(pcap, &filterprog);
    if (res !=0){
        cout << "setfilter make error " <<endl;
        help();
        exit(-3);
        
    }
    //открываем файл для записи и пишем данные
    pcap_dumper_t *dumpfile;
    try {
        FILE *pFile = fopen(output_file.c_str(), "wb"); // open for writing in binary mode
        if (pFile == NULL)
        {
            cout << "error to open output file\n" << endl;
            help();
            exit(-4);
        }
        
        dumpfile = pcap_dump_fopen(pcap, pFile);
        //  const struct sniff_ethernet *ethernet; /* The ethernet header */
        while (pcap_next_ex(pcap, &header, &data) >= 0) {
            //если используются параметр vlan
            if (vlan_flag){

                ethernet_h *ethernet = (struct ethernet_h*)(data);
                if (ntohs(ethernet->ether_type )== 0x8100){

                    u_short vlan = ntohs(*(u_short*)(data + sizeof(ethernet_h)));
                    if (std::find(vlans.begin(), vlans.end(), vlan ) != end(vlans) )
                    {
                        pcap_dump((unsigned char *) dumpfile, header, data);
                        continue;
                    }
                }
                //на случай сдвоенного vlan
                if (ntohs(*(u_short*)(data + sizeof(ethernet_h) + 2 ))== 0x8100){
                    u_short vlan = ntohs(*(u_short*)(data + sizeof(ethernet_h) + 4));
                    if (std::find(vlans.begin(), vlans.end(), vlan ) != end(vlans) )
                    {
                        pcap_dump((unsigned char *) dumpfile, header, data);
                        continue;
                    }
                }
                continue;
            }
            //остальные данные фильтруются библиотекой
            pcap_dump((unsigned char *) dumpfile, header, data);
            
        }
    }
    catch (...) {
        if (dumpfile != NULL)
            pcap_dump_close(dumpfile);
        help();
        exit(-4);
    }
    pcap_dump_close(dumpfile);
    
    return 0;
}
