#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in6.h>
#include <netinet/ip_icmp.h>

// +5 for ":", +1 for '\0'
#define MAC_ADDR_STRLEN 2*(MAX_ADDR_LEN-1) + 5 + 1

int dump_flag = 0;
int cnt = 0;

void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *packet);
void select_dev(const pcap_if_t *alldevsp, char dev[]);
void parse_ethernet(const u_char *packet);
void parse_ip(const u_char *packet);
void parse_arp(const u_char *packet);
void parse_tcp(const u_char *packet);
void parse_udp(const u_char *packet);
void check_tcpflag(char flags[], const struct tcphdr *tcp_hdr);
void show_supported_dlp(pcap_t *handle, char dev[], char errbuf[]);

int main(int argc, char *argv[]) {
    int ret, c;
    int pkt_n = 5; // default number of captured packets
    int sel_dev = 0, set_filter = 0;
    char *filter_arg, *saved_file;
#define DEV_LEN 32
    char errbuf[PCAP_ERRBUF_SIZE], dev[DEV_LEN];
    pcap_t *handle;
    pcap_if_t *alldevsp, *ptr;
    pcap_dumper_t *pdumper; // for saving packet captured
    bpf_u_int32 net, mask;
    struct bpf_program fp;

    // parse the command line
    while ((c = getopt(argc, argv, "cr:n:s:f:")) != -1) {
        switch (c) {
        // case reading the offline pcap file
        case 'r':
            handle = pcap_open_offline(optarg, errbuf);
            if (!handle) {
                fprintf(stderr, "pcap_open_offline : %s\n", errbuf);
                exit(1);
            }
            break;

        // case setting number of packets to read
        case 'n':
            pkt_n = atoi(optarg);
            break;

        // case reading packets online
        case 'c':
            ret = pcap_findalldevs(&alldevsp, errbuf);
            if (ret == PCAP_ERROR) {
                fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
                exit(1);
            }
            select_dev(alldevsp, dev);
            sel_dev = 1;

            handle = pcap_open_live(dev, 8192, 1, -1, errbuf);
            if (!handle) {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                exit(1);
            }
            break;

        // case store the online captured pcap file
        case 's': ; // ';' is needed for compiling
            int savedfile_arg_len = strlen(optarg);
            saved_file = (char *) malloc((savedfile_arg_len+1) * sizeof(char));
            strcpy(saved_file, optarg);
            saved_file[savedfile_arg_len] = '\0';

            // just set flag cause -c argument might not be parse
            // , whilch means handler might not be opened
            dump_flag = 1;
            break;
        
        // case setting filter
        case 'f': ; // ';' is needed for compiling
            int filter_arg_len = strlen(optarg);
            filter_arg = (char *) malloc(sizeof(char) * (filter_arg_len+1));
            strcpy(filter_arg, optarg);
            filter_arg[filter_arg_len] = '\0';

            set_filter = 1;
            break;
        
        default:
            break;
        }
    } // while getopt

    // we no longer need the device list
    pcap_freealldevs(alldevsp);

    // show the data link protocol the device supported if having selected device
    if (sel_dev)
        show_supported_dlp(handle, dev, errbuf);

    // set filter
    if (set_filter) {
        // get network and mask
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "Can't get netmask for device %s\n", dev);
            pcap_close(handle);
            exit(1);
        }

        // compile filter
        if (pcap_compile(handle, &fp, filter_arg, 1, mask) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_arg, pcap_geterr(handle));
            pcap_close(handle);
            exit(1);
        }

        // set filter
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_arg, pcap_geterr(handle));
            pcap_close(handle);
            exit(1);
        }

        printf("Sets filter: %s\n", filter_arg);

        pcap_freecode(&fp);
    } // if set filter
    
    // deal with -s argument
    if (dump_flag == 1) {
        pdumper = pcap_dump_open(handle, saved_file);
        if (!pdumper) {
            fprintf(stderr, "pcap_dump_open(): %s\n", pcap_geterr(handle));
            pcap_close(handle);
            exit(1);
        }
        printf("Saving packet captured to %s...\n", saved_file);
    }

    if (pcap_loop(handle, pkt_n, pcap_callback, (u_char *) pdumper) != 0)
        fprintf(stderr, "pcap_loop: %s\n", pcap_geterr(handle));

    // be cautious their will be some data left in buffer
    if (dump_flag)
        pcap_dump_flush(pdumper);

    pcap_close(handle);
}

// show the data link protocol the device supported
void show_supported_dlp(pcap_t *handle, char dev[], char errbuf[]) {
    int sup_len;
    int datalink_p;
    int *datalink_ps;

    // get the device's default datalink protocol and show
    datalink_p = pcap_datalink(handle);

    printf("\n%s's default supported protocol of datalink layer:\n", dev);
    printf("  Name: %s\n", pcap_datalink_val_to_name(datalink_p));
    printf("  Description: %s\n", pcap_datalink_val_to_description(datalink_p));

    // get all datalink supported protocol list of the device selected and show
    sup_len = pcap_list_datalinks(handle, &datalink_ps);
    if (sup_len == -1) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        pcap_close(handle);
        exit(1);
    }    

    printf("\nProtocols %s supported:\n", dev);
    for (int i=0; i<sup_len; i++) {
        datalink_p = datalink_ps[i];
        printf("  Name: %s\n", pcap_datalink_val_to_name(datalink_p));
        printf("  Description: %s\n\n", pcap_datalink_val_to_description(datalink_p));
    }

    // free
    pcap_free_datalinks(datalink_ps);
}

void select_dev(const pcap_if_t *alldevsp, char dev[]) {
    int flag = 0; // flag match device
    const pcap_if_t *ptr = alldevsp;

    printf("Device list:\n\n");
    while (ptr) {
        printf("  %s\n", ptr->name);
        ptr = ptr->next;
    }

    // loop until get the correct device name
    while (!flag) {
        printf("\nSelect a device to capture the packet: ");
        fgets(dev, DEV_LEN, stdin);
        ptr = alldevsp;
        dev[strlen(dev)-1] = '\0';

        // traverse to check the input
        while (ptr) {
            if (strcmp(dev, ptr->name) != 0) {
                ptr = ptr->next;
                continue;
            } else {
                flag = 1;
                break;
            }
        }
        if (flag) {
            printf("\nDevice selected: %s\n", dev);
        } else {
            printf("\nDevice selected(%s) not existed!", dev);
        }
    }
}

void pcap_callback(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("\nNo.%2d packet\n", ++cnt);
    
    // save packet
    if (dump_flag)
        pcap_dump(dumpfile, header, packet);

    // time info
    printf("Capture time: %s", ctime((time_t *) &header->ts.tv_sec));
    printf("Length: %d bytes\n", header->len);
    printf("Capture length: %d bytes\n", header->caplen);

    // print out info
    parse_ethernet(packet);

    return;
}

void parse_ethernet(const u_char *packet) {
    char mac_src_addr[MAC_ADDR_STRLEN], mac_dst_addr[MAC_ADDR_STRLEN];
    uint16_t eth_type;
    struct ether_header *eth_hdr;

    // parse the ether_header
    eth_hdr = (struct ether_header *) packet;

    // parse the source address
    snprintf(mac_src_addr, sizeof(mac_src_addr), "%02x:%02x:%02x:%02x:%02x:%02x"
            , eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2]
            , eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);

    // parse the source address
    snprintf(mac_dst_addr, sizeof(mac_dst_addr), "%02x:%02x:%02x:%02x:%02x:%02x"
            , eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2]
            , eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);

    // parse the ether_type
    eth_type = ntohs(eth_hdr->ether_type);

    // show output
    if(eth_type <= 1500)
        printf("\nIEEE 802.3 Ethernet Frame:\n");
    else
        printf("\nEthernet Frame\n");
    printf("+-------------------------+-------------------------+-------------------------+\n");
    printf("| Destination MAC Address:                                   %17s|\n", mac_dst_addr);
    printf("+-------------------------+-------------------------+-------------------------+\n");
    printf("| Source MAC Address:                                        %17s|\n", mac_src_addr);
    printf("+-------------------------+-------------------------+-------------------------+\n");
    if (eth_type < 1500)
        printf("| Length:            %5u|\n", eth_type);
    else
        printf("| Ethernet Type:    0x%04x|\n", eth_type);
    printf("+-------------------------+\n");

    switch (eth_type) {
        case ETHERTYPE_ARP:
            parse_arp(packet);
            break;

        case ETHERTYPE_IP:
            parse_ip(packet);
            break;

        case ETHERTYPE_REVARP:
            printf("Next is RARP packet\n");
            break;

        case ETHERTYPE_IPV6:
            printf("Next is IPv6 packet\n");
            break;

        default:
            printf("Next is %#06x", eth_type);
            break;
    } // end switch
}

void parse_ip(const u_char *packet) {
    char ip_flags[4] = {'\0'};
    struct ip *ip_hdr = (struct ip *) (packet + ETHER_HDR_LEN);

    // get info
    u_int header_len = ip_hdr->ip_hl << 2;
    u_int version = ip_hdr->ip_v;
    u_int16_t total_len = ntohs(ip_hdr->ip_len);
    u_int16_t id = ntohs(ip_hdr->ip_id);
    u_char ttl = ip_hdr->ip_ttl;
    u_char protocol = ip_hdr->ip_p;
    u_int16_t checksum = ntohs(ip_hdr->ip_sum);

    // deal with type of service
    uint8_t tos = ip_hdr->ip_tos;
    char ip_tos_flags[] = {'1', '1', '1', 'D', 'T', 'R', 'C', 'X', '\0'};
#define TOS_LEN (sizeof(ip_tos_flags) / sizeof(ip_tos_flags[0]))
    
    u_int8_t mask = 1 << 7; //mask
    int i;

    for (int i = 0; i < TOS_LEN-1; i++) {
        if(!(mask & tos))
            ip_tos_flags[i] = '-';
        mask >>= 1;
    }

    // catch ip flag
    u_int16_t offset = ntohs(ip_hdr->ip_off);
    
    switch (offset) {
    case IP_RF:
        ip_flags[0] = 'R';
        break;
    case IP_DF:
        ip_flags[1] = 'D';
        break;
    case IP_MF:
        ip_flags[2] = 'M';
        break;
    
    default:
        break;
    }
    
    // show output
    printf("\nIP Protocol\n");
    printf("+-----+------+------------+-------------------------+\n");
    printf("| IV:%1u| HL:%2u| T: %8s| Total Length: %10u|\n",
           version, header_len, ip_tos_flags, total_len);
    printf("+-----+------+------------+-------+-----------------+\n");
    printf("| Identifier:        %5u| FF:%3s| FO:        %5u|\n",
           id, ip_flags, offset & IP_OFFMASK);
    printf("+------------+------------+-------+-----------------+\n");
    printf("| TTL:    %3u| Pro:    %3u| Header Checksum:   %5u|\n",
           ttl, protocol, checksum);
    printf("+------------+------------+-------------------------+\n");
    printf("| Source IP Address:                 %15s|\n",  inet_ntoa(ip_hdr->ip_src));
    printf("+---------------------------------------------------+\n");
    printf("| Destination IP Address:            %15s|\n", inet_ntoa(ip_hdr->ip_dst));
    printf("+---------------------------------------------------+\n");

    // parse protocol
    switch (protocol) {
        case IPPROTO_UDP:
            parse_udp(packet);
            break;

        case IPPROTO_TCP:
            parse_tcp(packet);
            break;

        case IPPROTO_ICMP:
            printf("Next is ICMP\n");
            break;

        default:
            printf("Next is %d\n", protocol);
            break;
    } // end switch
}

void parse_arp(const u_char *packet) {
    struct ether_arp *arp_hdr = (struct ether_arp *) (packet + ETHER_HDR_LEN);
   
    
    // get info
    u_short hardware_format = ntohs(arp_hdr->ea_hdr.ar_hrd);
    u_short protocol_format = ntohs(arp_hdr->ea_hdr.ar_pro);
    u_char hardware_addr_len = arp_hdr->ea_hdr.ar_hln;
    u_char protocol_addr_len = arp_hdr->ea_hdr.ar_pln;
    u_short arp_opcode = ntohs(arp_hdr->ea_hdr.ar_op);

    
    // parse the MAC address
    char sender_mac_addr[MAC_ADDR_STRLEN], target_mac_addr[MAC_ADDR_STRLEN];

    snprintf(sender_mac_addr, sizeof(sender_mac_addr), "%02x:%02x:%02x:%02x:%02x:%02x"
            , arp_hdr->arp_sha[0], arp_hdr->arp_sha[1], arp_hdr->arp_sha[2]
            , arp_hdr->arp_sha[3], arp_hdr->arp_sha[4], arp_hdr->arp_sha[5]);

    snprintf(target_mac_addr, sizeof(target_mac_addr), "%02x:%02x:%02x:%02x:%02x:%02x"
            , arp_hdr->arp_tha[0], arp_hdr->arp_tha[1], arp_hdr->arp_tha[2]
            , arp_hdr->arp_tha[3], arp_hdr->arp_tha[4], arp_hdr->arp_tha[5]);

    // parse the protocol address
    char sender_protocol_addr[INET_ADDRSTRLEN], target_protocol_addr[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, (void *) arp_hdr->arp_spa, sender_protocol_addr, sizeof(sender_protocol_addr));
    inet_ntop(AF_INET, (void *) arp_hdr->arp_tpa, target_protocol_addr, sizeof(target_protocol_addr));


    static char *arp_op_name[] = {
        "Undefine",
        "(ARP Request)",
        "(ARP Reply)",
        "(RARP Request)",
        "(RARP Reply)"
    };

    if (arp_opcode < 0 || sizeof(arp_op_name)/sizeof(arp_op_name[0]) < arp_opcode)
        arp_opcode = 0;

    printf("\nARP Protocol\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Hard Type: %2u%-11s| Protocol:0x%04x%-9s|\n",
           hardware_format,
           (hardware_format == ARPHRD_ETHER) ? "(Ethernet)" : "(Not Ether)",
           protocol_format,
           (protocol_format == ETHERTYPE_IP) ? "(IP)" : "(Not IP)");
    printf("+------------+------------+-------------------------+\n");
    printf("| HardLen:%3u| Addr Len:%2u| OP: %4d%16s|\n",
           hardware_addr_len, protocol_addr_len, arp_opcode, arp_op_name[arp_opcode]);
    printf("+------------+------------+-------------------------+-------------------------+\n");
    printf("| Source MAC Address:                                        %17s|\n", sender_mac_addr);
    printf("+---------------------------------------------------+-------------------------+\n");
    printf("| Source IP Address:                 %15s|\n", sender_protocol_addr);
    printf("+---------------------------------------------------+-------------------------+\n");
    printf("| Destination MAC Address:                                   %17s|\n", target_mac_addr);
    printf("+---------------------------------------------------+-------------------------+\n");
    printf("| Destination IP Address:            %15s|\n", target_protocol_addr);
    printf("+---------------------------------------------------+\n");
}

void parse_tcp(const u_char *packet) {
    struct ip *ip_hdr = (struct ip *) (packet + ETHER_HDR_LEN);
    struct tcphdr *tcp_hdr = (struct tcphdr *) (packet + ETHER_HDR_LEN + (ip_hdr->ip_hl << 2));

    // get info
    char flags[9] = {'\0'};
    check_tcpflag(flags, tcp_hdr);
    
    u_int8_t header_len = tcp_hdr->doff << 2;
    u_int16_t window = ntohs(tcp_hdr->window);
    u_int16_t checksum = ntohs(tcp_hdr->check);
    u_int16_t urgent = ntohs(tcp_hdr->urg_ptr);

    // show output
    printf("\nTCP Protocol\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Source Port:       %5u| Destination Port:  %5u|\n", ntohs(tcp_hdr->source), ntohs(tcp_hdr->dest));
    printf("+-------------------------+-------------------------+\n");
    printf("| Sequence Number:                        %10u|\n", ntohl(tcp_hdr->seq));
    printf("+---------------------------------------------------+\n");
    printf("| Acknowledgement Number:                 %10u|\n", ntohl(tcp_hdr->ack_seq));
    printf("+------+-------+----------+-------------------------+\n");
    printf("| HL:%2u|  RSV  |F:%8s| Window Size:       %5u|\n", header_len, flags, window);
    printf("+------+-------+----------+-------------------------+\n");
    printf("| Checksum:          %5u| Urgent Pointer:    %5u|\n", checksum, urgent);
    printf("+-------------------------+-------------------------+\n");
}

void check_tcpflag(char flags[], const struct tcphdr *tcp_hdr) {
    if(tcp_hdr->cwr)
        flags[0] = 'W';
    else
        flags[0] = '-';
    if(tcp_hdr->ece)
        flags[1] = 'E';
    else
        flags[1] = '-';
    if(tcp_hdr->urg)
        flags[2] = 'U';
    else
        flags[2] = '-';
    if(tcp_hdr->ack)
        flags[3] = 'A';
    else
        flags[3] = '-';
    if(tcp_hdr->psh)
        flags[4] = 'P';
    else
        flags[4] = '-';
    if(tcp_hdr->rst)
        flags[5] = 'R';
    else
        flags[5] = '-';
    if(tcp_hdr->syn)
        flags[6] = 'S';
    else
        flags[6] = '-';
    if(tcp_hdr->fin)
        flags[7] = 'F';
    else
        flags[7] = '-';
}

void parse_udp(const u_char *packet) {
    struct ip *ip_hdr = (struct ip *) (packet + ETHER_HDR_LEN);
    struct udphdr *udp_hdr = (struct udphdr *) (packet + ETHER_HDR_LEN + (ip_hdr->ip_hl << 2));

    printf("\nUDP Protocol\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Source Port:       %5u| Destination Port:  %5u|\n", ntohs(udp_hdr->source), ntohs(udp_hdr->dest));
    printf("+-------------------------+-------------------------+\n");
    printf("| Length:            %5u| Checksum:          %5u|\n", ntohs(udp_hdr->len), ntohs(udp_hdr->check));
    printf("+-------------------------+-------------------------+\n");
}
