#ifndef ICMP_H_
#define ICMP_H_

#include <cstdio>
#include <arpa/inet.h>

/* Icmp Header */
struct IcmpHeader
{
    u_char  type;
    u_char  code;
    u_short checksum;
    u_short identifier;
    u_short sequence;
    u_short data;
};

class Icmp
{
public:
    Icmp();

    void parse_icmp_packet(const u_char*);
    void print_icmp_packet();

private:
    IcmpHeader* icmp_header;
    u_char code;
    u_short identifier;
    u_char type;
};

#endif // ICMP_H
