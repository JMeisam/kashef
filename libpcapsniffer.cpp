#include <stdio.h>
#include <ctime>
#include "libpcapsniffer.h"

LibpcapSniffer::LibpcapSniffer()
{

}

LibpcapSniffer::~LibpcapSniffer()
{
    pcap_close(pcap);
}

void LibpcapSniffer::dump_packet(const u_char* packet, const struct pcap_pkthdr*                             pcap_packet_header)

{
    (void)pcap_packet_header;
    Ethernet eth;

    eth.parse_ethernet_packet(packet);

    u_short ethernet_type = eth.get_ethernet_type();
    packet += Ethernet::ethernet_headr_len;

    if (ethernet_type == 0X0800)
    {
        IP ip;
        int ip_header_len;
        u_char ip_protocol;

        ip.parse_ip_packet(packet);
        ip.print_ip_packet();

        ip_header_len = ip.get_ip_header_length();
        ip_protocol = ip.get_ip_protocol();

        packet += (ip_header_len *4 );

        switch (ip_protocol)
        {

        case IPPROTO_TCP:
            break;

        case IPPROTO_UDP:
            break;

        case IPPROTO_ICMP:
            Icmp icmp;
            icmp.parse_icmp_packet(packet);
            icmp.print_icmp_packet();
            break;
        }
    }
    else if (ethernet_type == 0X0806)
    {
        Arp arp;
        arp.parse_arp_packet(packet);
        arp.print_arp_packet();
    }
    printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");

}

void LibpcapSniffer::open_packet_socket(char* file)
{
    char error_buffer[PCAP_ERRBUF_SIZE];

    pcap = pcap_open_offline(file, error_buffer);
    if (pcap == NULL)
    {
        fprintf(stderr, "Error reading pcap file: %s\n", error_buffer);
        return;
    }
}

void LibpcapSniffer::capture_loop()
{
    const unsigned char* packet;
    pcap_pkthdr pcap_packet_headr;

    while ((packet = pcap_next(pcap, &pcap_packet_headr)) !=NULL)
        this->dump_packet(packet, &pcap_packet_headr);
}
