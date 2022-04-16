#include<getopt.h>
#include <stdio.h>
#include <pcap.h>
//#include <bitset.h>
#include<arpa/inet.h>
#include <netinet/if_ether.h>
#include<netinet/ether.h>
#include<netinet/ip6.h>
#include<netinet/tcp.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<unistd.h>
#include<stdlib.h>
#include<stdio.h>
#include<stdbool.h>
#include<string.h>
#include<time.h>



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



    // https://stackoverflow.com/questions/7939238/dereferencing-pointer-to-incomplete-type-with-struct-ip-and-also-with-struct-iph
void PrintPacketInHex(char *mesg, unsigned char *p, int len){
    printf("%s", mesg);
    while(len--)
    {   
        if (len == 0)
            printf("%02X",*p);
        else
            printf("%02X:",*p);
        p++;
    }
}


void TimeStampCreating(char timeBuffer[100], struct pcap_pkthdr header)
{
    struct tm ts;
        ts = *localtime(&header.ts.tv_sec);
        int microseconds = header.ts.tv_usec;
        int miliseconds = microseconds/1000;



        strftime(timeBuffer, sizeof(char)*100, "%FT%T", &ts);

        char milisecondsBuffer[100] = {'\0'};

        sprintf(milisecondsBuffer, ".%03d", miliseconds);
        strcat(timeBuffer, milisecondsBuffer);

        tzset();
        int timeZone = -timezone/3600;

        if(timeZone < 0 )
            sprintf(milisecondsBuffer, "%03d:00", timeZone);
        else
        {
            sprintf(milisecondsBuffer, "+%02d:00", timeZone);
        }
        strcat(timeBuffer, milisecondsBuffer);


}

void FilterStringCreating(char filterString[], struct argFields argumentsOfprogram, struct bpf_program *filteredProgram)
{
    char ports[20] = {'\0'};

        //Create string for ports
    if (argumentsOfprogram.port == -1)
        sprintf(ports, "portrange 0-65535");
    else
        sprintf(ports, "port %d", argumentsOfprogram.port);

        //Creating filterString depends on program arguments
    if(argumentsOfprogram.tcp)
    {
        sprintf(filterString, "(tcp and %s)", ports);
    }

    if(argumentsOfprogram.udp)
    {
        char  helpString[100] = {'\0'};

        if(filterString[0] != '\0')
        {
            sprintf(helpString, "or (udp and %s)",ports );
            strcat(filterString, helpString);
        }
        else
        {
            sprintf(filterString, "(udp and %s)",ports );
        }
    }

    if(argumentsOfprogram.arp)
    {
        char  helpString[100] = {'\0'};

        if(filterString[0] != '\0')
        {
            sprintf(helpString, "or (arp)");
            strcat(filterString, helpString);
        }
        else
        {
            sprintf(filterString, "(arp)");
        }

    }

    if(argumentsOfprogram.icmp)
    {
        char  helpString[100] = {'\0'};

        if(filterString[0] != '\0')
        {
            sprintf(helpString, "or (icmp)");
            strcat(filterString, helpString);
        }
        else
        {
            sprintf(filterString, "(icmp)");
        }

    }
    
    if(!argumentsOfprogram.tcp && !argumentsOfprogram.udp && !argumentsOfprogram.arp && !argumentsOfprogram.icmp)
    {
        sprintf(filterString, "(tcp and %s) or (udp and %s) or (arp) or (icmp)", ports, ports);    
    }

}


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
            {
                argumentsOfprogram->port = atoi(argv[i]);
                if(argumentsOfprogram->port < 0)
                {
                    fprintf(stderr, "Invalid port number, number has to be > than -1\n");
                    exit(1);
                }
            }
            
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
            {
                argumentsOfprogram->n = atoi(argv[i]);
                if(argumentsOfprogram->n < 1)
                {
                    fprintf(stderr, "Invalid n number, number has to be > than 0\n");
                    exit(1);
                }
            }   
        }
        else 
        {
            fprintf(stderr, "Unknown program argument\n");
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
        
        // find the IPV4 network number and netmask for a device
    if(pcap_lookupnet(argumentsOfprogram.interface, &pNet, &pMask, errbuf) == -1)
    {
        fprintf(stderr, "Can't get netmask for device\n");
        exit(2);
    }

    //printf("interfcae: %s\n", argumentsOfprogram.interface);

        // Open connection on specific interface;
    connection = pcap_open_live(argumentsOfprogram.interface, BUFSIZ, 1, 1, errbuf);
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
    char filterString[100] = {'\0'};
    
    
        //Create filterString
    FilterStringCreating(filterString, argumentsOfprogram, &filteredProgram);
    
    if (pcap_compile(connection, &filteredProgram, filterString, 1, pNet) == -1)
    {
        
        fprintf(stderr, "Can't parse filter\n");
        exit(2);

    }

    if(pcap_setfilter(connection, &filteredProgram) == -1)
    {
        fprintf(stderr, "Can't install filter\n");
        exit(2);

    }
    
    struct pcap_pkthdr header;
    const u_char *packet;
    
    for(int i = 0; i < argumentsOfprogram.n; i++)
    {
        packet = pcap_next(connection, &header);
            //DLZKA framu
        printf("Header length %d, caplen: %d, ",header.len, header.caplen);
        char timeBuffer[100] = {'\0'};

        TimeStampCreating(timeBuffer, header);
            //TIMESTAMP
        printf("timestamp: %s\n", timeBuffer);
        

        
        struct ether_header *ethHeader = (struct ether_header *)packet;
            //PROTOKOL A JEHO str a dst MAC adresa
        printf("protocol : %x\n", ntohs(ethHeader->ether_type));
        PrintPacketInHex("destination MAC : ", ethHeader->ether_dhost,6);
        printf("\n");
        PrintPacketInHex("source MAC : ", ethHeader->ether_shost,6);
        printf("\n");
        
        if(ntohs(ethHeader->ether_type) == ETHERTYPE_IP)
        {
            struct ip * ipHeader = (struct ip*)(packet + 14);
            char ipBuffer[100] = {'\0'};
                //src a dest IP adresa
            printf("verzia: %d, protocol: %d, lenght: %d,destAdr: %s, srcAdr: %s, IHL: %d \n\n", ipHeader->ip_v, ipHeader->ip_p, ipHeader->ip_len, inet_ntop(AF_INET, &ipHeader->ip_dst.s_addr, ipBuffer, 100), inet_ntop(AF_INET, &ipHeader->ip_src.s_addr, ipBuffer, 100), ipHeader->ip_hl);

                // IPv4 nema fixnu dlzku headru, preto je v premenne ip_hl ulozena dlzka headru v 4 bytovych slovach, takze 32 bitov.
                // ip_hl nasobim 4 pretoze dlzka jedneho riadku v ipv4 hlavicke je 32 bitov - > 4 byty a IHL tym padom ukazuje pocet riadkov
            if(ipHeader->ip_p == 1)
            {   //ICMP protocol, neobsahuje porty
                struct icmphdr *icmpHeader = (struct icmphdr *)(packet + 14 + ipHeader->ip_hl*4);

            }
            else if(ipHeader->ip_p == 6)
            {   //TCP protocol, obsahuje porty
                struct tcphdr *tcpHeader = (struct tcphdr *)(packet + 14 + ipHeader->ip_hl*4);
                printf("TCP: destination port: %d, source port: %d\n", tcpHeader->th_dport, tcpHeader->th_sport);

            }
            else if(ipHeader->ip_p == 17)
            {   //UDP protocol, obsahuje porty
                struct udphdr *udpHeader = (struct udphdr *)(packet + 14 + ipHeader->ip_hl*4);
                printf("UDP: destination port: %d, source port: %d\n", udpHeader->uh_dport, udpHeader->uh_sport);

            }


        }
        else if (ntohs(ethHeader->ether_type) == ETHERTYPE_ARP)
        {       //ARP protocol, neobsahuje porty
            struct ether_arp * arpHeader = (struct ether_arp*)(packet + 14);
            char arpBuffer[100] = {'\0'};
            printf("ARP source ip: %s", inet_ntop(AF_INET, &arpHeader->arp_spa, arpBuffer, 100));
            printf("\n");
            printf("ARP destination ip: %s", inet_ntop(AF_INET, &arpHeader->arp_tpa, arpBuffer, 100));
            printf("\n\n");



        }
        else if(ntohs(ethHeader->ether_type) == ETHERTYPE_IPV6)
        {
            struct ip6_hdr * ip6Header = (struct ip6_hdr*)(packet + 14);
            char ip6Buffer[100] = {'\0'};
            printf("IPv6: destination address: %s, source address: %s \n", inet_ntop(AF_INET, &ip6Header->ip6_dst, ip6Buffer, 100), inet_ntop(AF_INET, &ip6Header->ip6_src, ip6Buffer, 100));

        }
        

    }

        // Close connection on interface
    pcap_close(connection);
    return 0;
}