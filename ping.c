#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <math.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <signal.h>

#define SIZE 1024
#define PKT_SIZE 64

int num_sent = 0, num_received = 0;

unsigned short cal_checksum(unsigned short *addr, int len)
{
    unsigned int sum = 0;
    while (len > 1)
    {
        sum += *addr;
        addr++;
        len -= 2;
    }
    if (len)
    {
        sum += *(unsigned char *)addr;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)~sum;
}

void sig_handler(int signo)
{
    if (signo == SIGINT)
    {
        printf("\n********** Program End **********\n");
        float loss=0;
        if(num_sent)
            loss=(num_sent - num_received) / num_sent* 100;
        printf("%d packets sent, %d received, %.2f%% packet loss\n", num_sent, num_received, loss);
        exit(0);
    }
    printf("received SIGINT\n");
}

int main(int argc, char *argv[])
{
    int c;
    char *target = NULL;
    int isIpv6 = 0;
    int ttl = 3000;
    while ((c = getopt(argc, argv, "4:6:t:")) != -1)
    {
        switch (c)
        {
        case '4':
            target = optarg;
            break;
        case '6':
            target = optarg;
            isIpv6 = 1;
            break;
        case 't':
            ttl = atoi(optarg);
            break;
        default:
            abort();
        }
    }
    if (target == NULL)
    {
        printf("Invalid argument! usage: ping [ -t ttl] [-4]/[-6] target\n");
        exit(0);
    }

    char *sendbuffer, *recvbuffer;
    sendbuffer = (char *)malloc(PKT_SIZE);
    memset(sendbuffer, 0, PKT_SIZE);
    recvbuffer = (char *)malloc(SIZE);
    memset(recvbuffer, 0, SIZE);

    int sock;
    socklen_t sin_size;
    struct sockaddr *addr;

    struct addrinfo *getaddrinfo_result, hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_RAW;

    if (getaddrinfo(target, NULL, &hints, &getaddrinfo_result) == 0)
    {
        addr = getaddrinfo_result->ai_addr;
    }
    else
    {
        printf("fail to getaddrinfo\n");
        exit(1);
    }

    if (isIpv6)
    {
        //create IPV6 raw socket
        if ((sock = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMP)) < 0)
        {
            perror("fail to create socket");
            exit(1);
        }
        // struct sockaddr_in6 sin;
        // sin_size=sizeof(sin);
        // memset (&sin, 0, sin_size);
        // //construct address
        // sin.sin6_family = AF_INET;
        // inet_pton (AF_INET6, target,  &sin.sin6_addr);
        // addr=(struct sockaddr*)&sin;
    }
    else
    {
        //create IPV4 raw socket
        if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
        {
            perror("fail to create socket");
            exit(1);
        }
        // struct sockaddr_in sin;
        // sin_size=sizeof(sin);
        // memset (&sin, 0, sin_size);
        // //construct address
        // sin.sin_family = AF_INET;
        // //if target is hostname
        // if (inet_pton (AF_INET, target,  &sin.sin_addr)==0)
        // {
        //     struct hostent *host;
        //     host = gethostbyname(target);
        //     if (host == NULL)
        //     {
        //         perror("fail to resolve target");
        //         exit(1);
        //     }
        //     memcpy((char *)&sin.sin_addr, host->h_addr, host->h_length);
        // }
        // addr=(struct sockaddr*)&sin;
    }

    struct timeval tv, start_tv;
    int i = 0, temp;
    struct icmp *icmp;
    int ipHeadLen;
    struct ip *ip;
    ip = (struct ip *)recvbuffer;
    double rtt;
    struct timeval *send_time;

    signal(SIGINT, sig_handler);

    while (1)
    {
        //wait a sec
        sleep(1);

        //constrcut icmp packet
        icmp = (struct icmp *)sendbuffer;
        icmp->icmp_type = ICMP_ECHO;
        icmp->icmp_code = 0;
        icmp->icmp_cksum = 0;
        icmp->icmp_seq = i;
        icmp->icmp_id = getpid();
        gettimeofday((struct timeval *)icmp->icmp_data, NULL); //to compute RTT, we need to store time in payload
        icmp->icmp_cksum = cal_checksum((unsigned short *)icmp, PKT_SIZE);

        //send out
        temp = sendto(sock, sendbuffer, PKT_SIZE, 0, addr, sin_size);
        num_sent++;
        if (temp < 0)
        {
            printf("Error in sending!\n");
            continue;
        }
        gettimeofday(&start_tv, NULL);
        //wait until recv
        while (1)
        {
            gettimeofday(&tv, NULL);
            if (((tv.tv_sec - start_tv.tv_sec) * pow(10., 6) + tv.tv_usec - start_tv.tv_usec) / pow(10., 3) > ttl)
            {
                printf("Time exceeded!\n");
                break;
            }
            temp = recvfrom(sock, recvbuffer, SIZE, MSG_DONTWAIT, addr, &sin_size);
            if (temp < 0)
            {
                continue;
            }
            ipHeadLen = ip->ip_hl << 2; //skip ip head
            icmp = (struct icmp *)(recvbuffer + ipHeadLen);
            //check out whether the packet is correct
            if (temp - ipHeadLen < PKT_SIZE)
            {
                printf("Incomplete ICMP packet\n");
                continue;
            }
            if (icmp->icmp_id != getpid())
            {
                printf("Not my ICMP reply\n");
                continue;
            }
            if (icmp->icmp_type == ICMP_ECHOREPLY)
            {
                gettimeofday(&tv, NULL);
                send_time = (struct timeval *)icmp->icmp_data;
                //compute RTT
                rtt = ((tv.tv_sec - send_time->tv_sec) * pow(10., 6) + tv.tv_usec - send_time->tv_usec) / pow(10., 3);
                printf("icmp_seq is %u, RTT is %.3f ms\n", icmp->icmp_seq, rtt);
                num_received++;
                break;
            }
            else
            {
                printf("Not an ICMP reply \n");
            }
        }
        i++;
    }

    return 0;
}