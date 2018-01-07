#include "Ethernet.h"

Ethernet::Ethernet()
{

}

void Ethernet::parse_ethernet_packet(const u_char *packet)
{
    this->ethernet_header = (EthernetHeadr*)packet;
    printf("Ethernet, ");
    sprintf(this->source_mac, "%02X:%02x:%02x:%02x:%02x:%02x",
            this->ethernet_header->source_mac.hex1,
            this->ethernet_header->source_mac.hex2,
            this->ethernet_header->source_mac.hex3,
            this->ethernet_header->source_mac.hex4,
            this->ethernet_header->source_mac.hex5,
            this->ethernet_header->source_mac.hex6);
    printf("Src: %s, ", this->source_mac);
    sprintf(this->destination_mac, "%02X:%02x:%02x:%02x:%02x:%02x",
            this->ethernet_header->destination_mac.hex1,
            this->ethernet_header->destination_mac.hex2,
            this->ethernet_header->destination_mac.hex3,
            this->ethernet_header->destination_mac.hex4,
            this->ethernet_header->destination_mac.hex5,
            this->ethernet_header->destination_mac.hex6);
    printf("Dst: %s\n", this->destination_mac);
    this->type = ntohs(this->ethernet_header->type);

}

char* Ethernet::get_source_mac()
{
    return this->source_mac;
}

char *Ethernet::get_destination_mac()
{
    return this->destination_mac;
}

u_short Ethernet::get_ethernet_type()
{
    return this->type;
}

