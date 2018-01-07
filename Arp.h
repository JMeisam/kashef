#ifndef ARP_H
#define ARP_H

#include <cstdio>
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

/* ARP Header */
struct ArpHeader
{
    u_short hardware_type;
    u_short protocol_type;
    u_char hardware_address_length;
    u_char protocol_address_length;
    u_short operation_code;
    MacAddres sender_hardware_address;
    in_addr sender_ip_address;
    MacAddres target_hardware_address;
    in_addr target_ip_address;

};

class Arp
{
public:
    static const int mac_address_size = 20;

    Arp();

    void parse_arp_packet(const u_char*);
    void print_arp_packet();

private:
    ArpHeader* arp_header;
    MacAddres sender_hardware_address[mac_address_size];
    in_addr sender_ip_address;
    MacAddres target_hardware_address[mac_address_size];
    in_addr target_ip_address;
};

#endif // ARP_H
