#ifndef SEND_H
#define SEND_H


//#include <pfring.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pcap/pcap.h>
#include <libnet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include <regex>
#include <regex.h>

#include <time.h>

#include <QThread>
#include <QDebug>


using namespace std;


class Send : public QThread
{
public:
    Send(char* dev, const u_char *pkt=NULL, char* srcmac=NULL, char* dstmac=NULL,int proto=0, char* srcip=0, char* dstip=0, int id=0, int tos=0, int ttl=0, int iphlen=0, int tollen=0, int seq=0, int ack=0, int win=0, int tcphlen=0, int srcport=0, int dstport=0/* char* text=NULL*/);
    ~Send();

    struct timespec ts;

    pcap_t *handle;
//    pfring *pfhandle;
    const u_char *packet;
//    unsigned char* packet;
    char dev[10];
    char src_mac[20];
    char dst_mac[20];
    char src_ip[20];
    char dst_ip[20];
    int src_port;
    int dst_port;
    uint8_t S_mac[6];
    uint8_t D_mac[6];
//    char newtext[1500];
    int proto;
    int id;
    int tos;
    int ttl;
    int iphlen;
    int tollen;
    int seq=-1;
    int ack=-1;
    int win=-1;
    int tcphlen=-1;
    int old_iphlen=0;

    int size;
    long long send_bytes = 0;
    long long send_pks = 0;


private:
    void sendPkt(const u_char *pkt);
    void strToMac(char* str, int flag);

protected:
    void run();
signals:
    void done(void);
};

#endif // SEND_H
