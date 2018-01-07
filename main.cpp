#include <signal.h>
#include "libpcapsniffer.h"

int main(int argc, char **argv)
{
    LibpcapSniffer sniffer;
    char file_name[256] = "";
    int packets = 0, c;

    //Get command line options
    while ((c = getopt(argc, argv, "hf:n")) != -1) {

        switch (c) {
        case 'h':
            printf("Usage: %s [-h] [-f] [-n] []\n", argv[0]);
            exit(0);
            break;
        case 'f':
            strcpy(file_name, optarg);
            break;
        case 'n':
            packets = atoi(optarg);
        default:
            break;
        }
    }
    sniffer.open_packet_socket(file_name);
    sniffer.capture_loop();
    return 0;
}
