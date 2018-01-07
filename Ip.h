#ifndef IP_H
#define IP_H

#include <cstdio>
#include <arpa/inet.h>

/* IP Header */
struct IpHeader
{
    u_char version_header_len;
    u_char service_type;
    u_short total_length;
    u_short identification;
    u_short fragment_offset;
    u_char ttl;
    u_char protocol;
    u_short checksum;
    in_addr source_ip_address;
    in_addr destination_ip_address;
};

class IP
{
public:
    IP();

    void parse_ip_packet(const u_char*);
    void print_ip_packet();
    u_char get_ip_protocol();
    int get_ip_header_length();
    in_addr get_source_ip();
    in_addr get_destination_ip();

private:
    IpHeader *ip_header;
    in_addr source_ip;
    in_addr destination_ip;
    u_char ip_protocol;
    int ip_headr_lenght;
};

#endif // IP_H
