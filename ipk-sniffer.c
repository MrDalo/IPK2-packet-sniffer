#include<getopt.h>
#include <stdio.h>
#include <pcap.h>
//#include <bitset.h>
#include<arpa/inet.h>
#include<netinet/ether.h>
#include<netinet/ip6.h>
#include<netinet/tcp.h>
#include<netinet/ip_icmp.h>
#include<unistd.h>
#include<stdlib.h>
#include<stdio.h>
#include<stdbool.h>
#include<string.h>

struct argFields 
{
    char* interface;
    int port;
    int n;
    bool tcp;
    bool udp;
    bool arp;
    bool icmp;

};


static struct option long_options[] =
{
    {"interface", optional_argument, NULL, 'i'},
    {"tcp", no_argument, NULL, 't'},
    {"udp", no_argument, NULL, 'u'},
    {"arp", no_argument, NULL, 'a'},
    {"icmp", no_argument, NULL, 'c'},
    {NULL, 0, NULL, 0}
};


void DisplayAllAvailableInterfaces()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;

    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in function pcap_findalldevs\n");
        exit(1);
    }

    device = alldevs;
    
    int index = 1;
    printf("List of all interfaces: \n");
    while(device != NULL)
    {
        printf("%d. %s\n",index, device->name);
        device = device->next;
        index++;
    }

    pcap_freealldevs(alldevs);
}


void ArgumentProcessing(struct argFields *argumentsOfprogram, int argc, char *argv[] )
{


    for(int i = 1; i < argc; i++)
    {
    
        if(!strcmp(argv[i],"--interface") || !strcmp(argv[i],"-i"))
        {
            i++;
            if( i < argc && argv[i][0] != '-')
            {
                argumentsOfprogram->interface = argv[i];
            }
            else
                i--;

        }
        else if(!strcmp(argv[i],"-p"))
        {
            i++;
            if (i < argc)
                argumentsOfprogram->port = atoi(argv[i]);
            
        }
        else if(!strcmp(argv[i],"--tcp") || !strcmp(argv[i], "-t"))
        {
            argumentsOfprogram->tcp = true;
        }
        else if(!strcmp(argv[i],"--udp") || !strcmp(argv[i], "-u"))
        {
            argumentsOfprogram->udp = true;
        }
        else if(!strcmp(argv[i],"--arp"))
        {
            argumentsOfprogram->arp = true;
        }
        else if(!strcmp(argv[i],"--icmp"))
        {
            argumentsOfprogram->icmp = true;
        }
        else if(!strcmp(argv[i],"-n"))
        {
            i++;
            if (i < argc)
                argumentsOfprogram->n = atoi(argv[i]);
        }
        else 
        {
            fprintf(stderr, "Unknown2 program argument\n");
            exit(1);
        }


        
    }
    
}


int main(int argc, char *argv[])
{
    
    int opt;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;
    struct argFields argumentsOfprogram = {NULL, -1, 1, false, false, false, false};
    bpf_u_int32 pMask;
    bpf_u_int32 pNet;
    pcap_t *connection;

    ArgumentProcessing(&argumentsOfprogram, argc, argv);
    //printf("%s, %d, %d, %d, %d, %d, %d\n", argumentsOfprogram.interface, argumentsOfprogram.port, argumentsOfprogram.n, argumentsOfprogram.tcp, argumentsOfprogram.udp, argumentsOfprogram.arp, argumentsOfprogram.icmp);

    
    if (argumentsOfprogram.interface == NULL)
    {
        DisplayAllAvailableInterfaces();
        exit(0);
    }
        
        //TODO find the IPV4 network number and netmask for a device
    if(pcap_lookupnet(argumentsOfprogram.interface, &pNet, &pMask, errbuf) == -1)
    {
        fprintf(stderr, "Can't get netmask for device\n");
        exit(2);
    }

    //printf("interfcae: %s\n", argumentsOfprogram.interface);

        // Open connection on specific interface;
    connection = pcap_open_live(argumentsOfprogram.interface, BUFSIZ, 1, 1000, errbuf);
    if(connection == NULL)
    {
        fprintf(stderr, "Can't open connection on interface due to: %s\n", errbuf);
        exit(2);
    }

    if(pcap_datalink(connection) != DLT_EN10MB)
    {
        fprintf(stderr, "Interface  %s does not provide Ethernet headers - not supported\n", argumentsOfprogram.interface);
        exit(2);
    }

    struct bpf_program filteredProgram;
    
    if (pcap_compile(connection, &filteredProgram, "(tcp and port 22) or (udp and port 22) or (arp) or (icmp)", 1, pNet) == -1)
    {
        
        fprintf(stderr, "Can't parse filter\n");
        exit(2);

    }

    if(pcap_setfilter(connection, &filteredProgram) == -1)
    {
        fprintf(stderr, "Can't install filter\n");
        exit(2);

    }

        // Close connection on interface
    pcap_close(connection);
    return 0;
}