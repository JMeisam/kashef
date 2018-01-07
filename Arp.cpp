#include "Arp.h"

Arp::Arp()
{

}

void Arp::parse_arp_packet(const u_char* packet)
{
    arp_header = (struct ArpHeader*)packet;

    sprintf(this->sender_hardware_address, "%02X:%02x:%02x:%02x:%02x:%02x",
            this->arp_header->sender_hardware_address.hex1,
            this->arp_header->sender_hardware_address.hex2,
            this->arp_header->sender_hardware_address.hex3,
            this->arp_header->sender_hardware_address.hex4,
            this->arp_header->sender_hardware_address.hex5,
            this->arp_header->sender_hardware_address.hex6,
            );
    sprintf(this->target_hardware_address, "%02X:%02x:%02x:%02x:%02x:%02x",
            this->arp_header->target_hardware_address.hex1,
            this->arp_header->target_hardware_address.hex2,
            this->arp_header->target_hardware_address.hex3,
            this->arp_header->target_hardware_address.hex4,
            this->arp_header->target_hardware_address.hex5,
            this->arp_header->target_hardware_address.hex6
            );
}

void Arp::print_arp_packet()
{
    printf("Address Resolustion Protocol\n");
    printf("\t Sender MAC Address: %s\n", this->sender_hardware_address);
    printf("\t Sender IP Address: %s\n", inet_ntoa(this->sender_ip_address));
    printf("\t Target MAC Address: %s\n", this->target_hardware_address);
    printf("\t Target IP Address: %s\n", inet_ntoa(this->target_ip_address));



}

