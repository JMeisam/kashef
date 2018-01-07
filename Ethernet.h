#ifndef ETHERNET_H_
#define ETHERNET_H_

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

/* Mac Address */
struct MacAddres
{
    u_char hex1;
    u_char hex2;
    u_char hex3;
    u_char hex4;
    u_char hex5;
    u_char hex6;
};

/* Ethernet Header */
struct EthernetHeadr
{
    MacAddres source_mac;
    MacAddres destination_mac;
    u_short type;       /* IP? ARP? RARP? */
};

enum  class EthernetType
{
    ETHERTYPE_IP     = 0X0800,
    ETHERTYPE_ARP    = 0X0806,
    ETHERTYPE_REVARP = 0X8035
};


class Ethernet
{
public:
    static const int mac_address_size = 20;
    static const int ethernet_headr_len = 14;


    Ethernet();

    void parse_ethernet_packet(const u_char*);
    char* get_source_mac();
    char* get_destination_mac();
    u_short get_ethernet_type();

private:
    EthernetHeadr* ethernet_header;
    char source_mac[mac_address_size];
    char destination_mac[mac_address_size];
    u_short type;
};

#endif // ETHERNET_H
