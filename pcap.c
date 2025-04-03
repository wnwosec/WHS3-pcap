#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h> 
#include <netinet/ip.h>    
#include <netinet/tcp.h>   
#include <arpa/inet.h>    

#define MAX_PAYLOAD_SIZE 32  


void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

    struct ether_header *eth_header = (struct ether_header *)packet;


    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));


        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);


            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);


            uint16_t src_port = ntohs(tcp_header->th_sport);
            uint16_t dst_port = ntohs(tcp_header->th_dport);


            int ip_header_len = ip_header->ip_hl * 4; 
            int tcp_header_len = tcp_header->th_off * 4;  
            int tcp_data_offset = sizeof(struct ether_header) + ip_header_len + tcp_header_len;
            int tcp_data_length = pkthdr->len - tcp_data_offset;


            printf("\n[Ethernet Header]\n");
            printf("  Src MAC: %s\n", ether_ntoa((struct ether_addr *)eth_header->ether_shost));
            printf("  Dst MAC: %s\n", ether_ntoa((struct ether_addr *)eth_header->ether_dhost));


            printf("\n[IP Header]\n");
            printf("  Src IP: %s\n", src_ip);
            printf("  Dst IP: %s\n", dst_ip);


            printf("\n[TCP Header]\n");
            printf("  Src Port: %u\n", src_port);
            printf("  Dst Port: %u\n", dst_port);


            printf("\n[Payload]\n");
            if (tcp_data_length > 0) {
                printf("  Message: ");
                int print_size = (tcp_data_length > MAX_PAYLOAD_SIZE) ? MAX_PAYLOAD_SIZE : tcp_data_length;
                for (int i = 0; i < print_size; i++) {
                    char ch = packet[tcp_data_offset + i];
                    printf("%c", (ch >= 32 && ch <= 126) ? ch : '.');  
                }
                printf("\n");
            } else {
                printf("  No payload data.\n");
            }
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE]; 
    pcap_t *handle;  


    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return 1;
    }


    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Error compiling filter expression\n");
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter\n");
        return 1;
    }

    
    printf(" Sniffing TCP packets on device: eth0\n");
    pcap_loop(handle, 0, packet_handler, NULL);

    
    pcap_close(handle);
    return 0;
}
