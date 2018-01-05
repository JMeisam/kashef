#include <signal.h>
#include "libpcapsniffer.h"

int main(int argc, char **argv)
{
    LibpcapSniffer Sniffer;
    char interface[256] = "";
    int packets = 0, c;

    //Get command line options
    while ((c = getopt(argc, argv, "hi:n")) != -1) {

        switch (c) {
        case 'h':
            printf("Usage: %s [-h] [-i] [-n] []\n", argv[0]);
            exit(0);
            break;
        case 'i':
            strcpy(interface, optarg);
            break;
        case 'n':
            packets = atoi(optarg);
        default:
            break;
        }
    }
    pcap_t* pd;
    if ((pd = Sniffer.OpenPcapSocket(interface))) {
        Sniffer.SetMaxNumOfPacket(packets);
        Sniffer.CaptureLoop(pd);
    }
    pcap_close(pd);
    return 0;
}
