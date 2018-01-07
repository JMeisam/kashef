#include "Icmp.h"

Icmp::Icmp()
{

}

void Icmp::parse_icmp_packet(const u_char* packet)
{
    icmp_header = (struct IcmpHeader*)packet;

    this->code = icmp_header->code;
    this->type = icmp_header->type;
    this->identifier = ntohs(icmp_header->identifier);
}

void Icmp::print_icmp_packet()
{
    printf("Internet Contorl Message Protocol\n");
}

