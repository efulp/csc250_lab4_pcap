/**
 * This program reads a pcap file and prints the a summery of each packet heder, then summary statistics
 * about all the packets. top 5 most frequent letters (upper or lower case). The pcap file name is 
 * provided using command line arguments. If the file name is not provided or the file is not readable, 
 * the program will exit and provide an error message.
 *
 * @author Your Name Here {@literal <pluf@wfu.edu>}
 * @date Sept. 23, 2021
 * @assignment Lab 4
 * @course CSC 250
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#include <pcap.h>

int packet_OK(const unsigned char **packet, unsigned int capture_len);
void process_packet(const unsigned char *packet);  


int main(int argc, char *argv[]) {
    pcap_t *pcap;                    /* pcap file */
    const unsigned char *packet;     /* packet bytes */
    struct pcap_pkthdr header;       /* pcap header */
    char errbuf[PCAP_ERRBUF_SIZE];   /* buffer for error message */
    int num_pkt = 0;                 /* number of legal packets */

    /* we expect exactly one argument, the name of the file to dump. */
    if(argc < 2) {
        fprintf(stderr, "Usage: %s pcap_file \n", argv[0]);
        return 1;
    }

    pcap = pcap_open_offline(argv[1], errbuf);
    if(pcap == NULL) {
        fprintf(stderr, "error reading pcap file: %s\n", errbuf);
        return 1;
    }


    /* read all the packets in the pcap file */  
    while((packet = pcap_next(pcap, &header)) != NULL) {
        if(packet_OK(&packet, header.caplen)) {  
            process_packet(packet); 
            num_pkt++;  
        }
    }

    printf("---------------------------------------------------------------------------------------- \n");
    printf("%s, num pkt %d \n", argv[1], num_pkt);  

    return 0;
}


/**
 * Returns true if the packet is legit (a full capture), otherwise it returns false
 *
 * packet is a pointer to the packet pointer, it may be adjusted (hence the **)
 * capture_len is the packet length 
 **/
int packet_OK(const unsigned char **packet, unsigned int capture_len) {
    /* let's only process Ethernet frames */
    if(capture_len < sizeof(struct ether_header)) {
        return 0;
    }

    /* skip over the Ethernet frame  */
    *packet += sizeof(struct ether_header);
    capture_len -= sizeof(struct ether_header);

    /* make certain this is a legitimate packet */ 
    if(capture_len < sizeof(struct ip)) { 
        return 0;
    }

    /* we passed all the checks, so return true */  
    return 1;
}


/**
 * Processes a packet, displays the packst summary, and updates the pcap stats
 * Most of the work for this program is done here...
 **/
void process_packet(const unsigned char *packet) {
    unsigned char ttl = packet[8];
    printf("[TTL: %d] \n", ttl);  
}


