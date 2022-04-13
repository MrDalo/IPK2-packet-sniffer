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



int main(int argc, char *argv[])
{
    
    int opt;
    struct argFields argumentsOfprogram = {NULL, -1, 1, false, false, false, false};


    // :: means optional argument, : means required
    // while((opt = getopt_long(argc, argv, "i::p:tun:", long_options, NULL)) != -1)
    // {
    //     char *errorIndex = NULL;
    //     //printf("%c, %s, %d\n",opt, optarg, optind );
    //     switch (opt)
    //     {
    //         case 'i':
    //             argumentsOfprogram.interface = optarg;
    //             break;
    //         case 'p':
    //             printf("%s\n", optarg);
    //             if (optarg[0] == '-')
    //             {
    //                 fprintf(stderr, "Invalid port argument\n");
    //                 exit(2);
    //             }
    //             argumentsOfprogram.port = strtol(optarg,&errorIndex,10);
               
    //             // printf("port: %s\n", errorIndex);
    //             // if (errorIndex != NULL)
    //             // {
    //             //     fprintf(stderr, "Invalid 1port argument\n");
    //             //     exit(2);
    //             // }
               
    //             if (argumentsOfprogram.port < 0)
    //             {
    //                 fprintf(stderr, "Invalid port number\n");
    //                 exit(2);
    //             }

    //             break;
    //         case 't':
    //             argumentsOfprogram.t = true;
    //             break;
    //         case 'u':
    //             argumentsOfprogram.u = true;
    //             break;
    //         case 'n':
    //             if (optarg[0] == '-')
    //             {
    //                 fprintf(stderr, "Invalid Number of packets argument\n");
    //                 exit(2);
    //             }
    //             // argumentsOfprogram.n = strtol(optarg,&errorIndex,10);

    //             // if (errorIndex != NULL)
    //             // {
    //             //     fprintf(stderr, "Invalid Number1 of packets argument\n");
    //             //     exit(2);
    //             // }


    //             if (argumentsOfprogram.n < 1)
    //             {
    //                 fprintf(stderr, "Invalid Number of packets number\n");
    //                 exit(2);
    //             }
    //             break;
    //         case 'a':
    //             argumentsOfprogram.a = true;
    //             break;
    //         case 'c':
    //             argumentsOfprogram.c= true;
    //             break;
    //         case '?':
    //             fprintf(stderr, "Unknown program argument\n");
    //             break;
            

    //         default:
    //             break;
    //     }




    // }
    
    for(int i = 1; i < argc; i++)
    {
    
        if(!strcmp(argv[i],"--interface") || !strcmp(argv[i],"-i"))
        {
            i++;
            if( i < argc && argv[i][0] != '-')
            {
                argumentsOfprogram.interface = argv[i];
            }
            else
                i--;

        }
        else if(!strcmp(argv[i],"-p"))
        {
            i++;
            if (i < argc)
                argumentsOfprogram.port = atoi(argv[i]);
            
        }
        else if(!strcmp(argv[i],"--tcp") || !strcmp(argv[i], "-t"))
        {
            argumentsOfprogram.tcp = true;
        }
        else if(!strcmp(argv[i],"--udp") || !strcmp(argv[i], "-u"))
        {
            argumentsOfprogram.udp = true;
        }
        else if(!strcmp(argv[i],"--arp"))
        {
            argumentsOfprogram.arp = true;
        }
        else if(!strcmp(argv[i],"--icmp"))
        {
            argumentsOfprogram.icmp = true;
        }
        else if(!strcmp(argv[i],"-n"))
        {
            i++;
            if (i < argc)
                argumentsOfprogram.n = atoi(argv[i]);
        }
        else 
        {
            fprintf(stderr, "Unknown2 program argument\n");
            exit(1);
        }


        
    }
    
    printf("%s, %d, %d, %d, %d, %d, %d\n", argumentsOfprogram.interface, argumentsOfprogram.port, argumentsOfprogram.n, argumentsOfprogram.tcp, argumentsOfprogram.udp, argumentsOfprogram.arp, argumentsOfprogram.icmp);

    return 0;
}