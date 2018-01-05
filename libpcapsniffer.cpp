#include <stdio.h>
#include <ctime>
#include "libpcapsniffer.h"

int LibpcapSniffer::linkhdrlen_ = 0;

void LibpcapSniffer::PktCallback(u_char *args, const struct pcap_pkthdr *hdr,
                                 const u_char *packet)
{
    (void)args;
    (void)hdr;
    //const struct SniffEthernet* ethernet;
    const struct SniffIP* iphdr;
    const struct SniffTcp* tcphdr;
    const struct SniffUdp* udphdr;
    const struct IcmpHeader *icmphdr;
    //const char* payload;
    char iphdrinfo[256], srcip[256], destip[256];
    unsigned short id, seq;

    static int count = 0;
    count++;


    //ethernet = (struct SniffEthernet*)(packet);
    packet += linkhdrlen_;
    iphdr = (struct SniffIP *)packet;

    sprintf(srcip, "%c.%c.%c.%c", iphdr->ip_src2.byte1, iphdr->ip_src2.byte2,
            iphdr->ip_src2.byte3, iphdr->ip_src2.byte4);
    sprintf(srcip, "%c.%c.%c.%c", iphdr->ip_dst2.byte1, iphdr->ip_dst2.byte2,
            iphdr->ip_dst2.byte3, iphdr->ip_dst2.byte4);
    sprintf(iphdrinfo, "ID:%d TOS:0x%x, TTL: %d, IpLen:%d DgLen: %d",
            ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
            IP_HL(iphdr)*4, ntohs(iphdr->ip_len));

    packet += IP_HL(iphdr)*4;
    switch (iphdr->ip_p) {
    case IPPROTO_TCP:
        tcphdr = (struct SniffTcp*)packet;
        printf("TCP %s:%d -> %s:%d\n", srcip, ntohs(tcphdr->th_sport),
               destip, ntohs(tcphdr->th_dport));
        printf("%s\n", iphdrinfo);
        printf("%c%c%c%c%c%c Seq: 0X%x Ack: 0x%x Win: 0X%x TcpLen: %d\n",
               ((tcphdr->th_flags & TH_FIN) ?  'F' : '*'),
               ((tcphdr->th_flags & TH_SYN) ?  'S' : '*'),
               ((tcphdr->th_flags & TH_RST) ?  'R' : '*'),
               ((tcphdr->th_flags & TH_PUSH) ? 'P' : '*'),
               ((tcphdr->th_flags & TH_ACK) ?  'A' : '*'),
               ((tcphdr->th_flags & TH_URG) ?  'U' : '*'),
               ntohl(tcphdr->th_seq), ntohl(tcphdr->th_ack),
               ntohs(tcphdr->th_win), 4 * TH_OFF(tcphdr));
        break;
    case IPPROTO_UDP:
        udphdr = (struct SniffUdp *)packet;
        printf("UDP %s:%d -> %s:%d\n", srcip, ntohs(udphdr->sport),
               destip, ntohs(udphdr->dport));
        printf("%s\n", iphdrinfo);
        break;
    case IPPROTO_ICMP:
        icmphdr = (struct IcmpHeader *)packet;
        printf("ICMP %s -> %s\n", srcip, destip);
        printf("%s\n", iphdrinfo);
        memcpy(&id, (u_char *)icmphdr + 4, 2);
        memcpy(&seq, (u_char *)icmphdr + 6, 2);
        printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->type, icmphdr->code,
               ntohs(id), ntohs(seq));
        break;
    }
    printf(
            "-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");

}

LibpcapSniffer::LibpcapSniffer()
{
    packets_ = 0;
}

LibpcapSniffer::~LibpcapSniffer()
{

}

pcap_t *LibpcapSniffer::OpenPcapSocket(char* device)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pd;
    u_int32_t srcip, netmask;

    //If no network interface is specified, get first one
    if (!*device && !(device = pcap_lookupdev(errbuf))) {
        fprintf(stdout, "pcap_lockupdev(): %s\n", errbuf);
        return NULL;
    }

    //Open the dvice for live capture
    if ((pd = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL) {
        fprintf(stdout, "pcap_open_live: %s\n", errbuf);
        return NULL;
}
    //Get network device source IP address and netmask
    if (pcap_lookupnet(device, &srcip, &netmask, errbuf) < 0) {
        fprintf(stdout, "pcap_lookupnet: %s\n", errbuf);
        return NULL;
    }

    return pd;
}

void LibpcapSniffer::CaptureLoop(pcap_t* pd)
{
    int linktype;

    //Determine the datalink layer type
    if ((linktype = pcap_datalink(pd)) < 0) {
        fprintf(stdout, "pcap_datalink: %s\n", pcap_geterr(pd));
        return;
    }

    //Set the datalink layer header size
    switch (linktype) {
    case DLT_NULL:
        linkhdrlen_ = 4;
        break;
    case DLT_EN10MB:
        linkhdrlen_ = 14;
    case DLT_SLIP:
    case DLT_PPP:
        linkhdrlen_ = 24;
        break;
    default:
        fprintf(stdout, "Unsupported datalink (%d)\n", linktype);
        break;
    }

    //Start capturing packets.
    if (pcap_loop(pd, packets_, PktCallback, (u_char*)0) < 0) {
        fprintf(stdout, "pcap_loop failed: %s\n", pcap_geterr(pd));
        return;

    }
}

void LibpcapSniffer::SetMaxNumOfPacket(int packets)
{
    packets_ = packets;
}

void LibpcapSniffer::SetFilter(std::string)
{

}
