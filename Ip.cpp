#include "Ip.h"

IP::IP()
{

}

void IP::parse_ip_packet(const u_char *packet)
{
    ip_header = (struct IpHeader*)packet;

    source_ip = ip_header->source_ip_address;
    destination_ip = ip_header->destination_ip_address;
    ip_headr_lenght = (ip_header->version_header_len & 0X0F);
}

void IP::print_ip_packet()
{
    printf("Internet Protocol Version 4, Src: %s, Dst: %s\n",
           inet_ntoa(this->source_ip), inet_ntoa(this->destination_ip));
}

u_char IP::get_ip_protocol()
{
    return this->ip_protocol;
}

int IP::get_ip_header_length()
{
    return this->ip_headr_lenght;
}

in_addr IP::get_source_ip()
{
    return this->source_ip;
}

in_addr IP::get_destination_ip()
{
    return this->destination_ip;
}

