#ifndef SENDER_H
#define SENDER_H

//#include <pfring.h>
#include "send.h"
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

#include <QMap>
#include <QThread>
#include <QDebug>

#include <QDialog>

#include <iostream>

using namespace std;

struct arp_hdr2
{
    unsigned short int ar_hrd;		/* Format of hardware address.  */
    unsigned short int ar_pro;		/* Format of protocol address.  */
    unsigned char ar_hln;		/* Length of hardware address.  */
    unsigned char ar_pln;		/* Length of protocol address.  */
    unsigned short int ar_op;		/* ARP opcode (command).  */

    unsigned char ar_sha[ETH_ALEN];	/* Sender hardware address.  */
    unsigned char ar_sip[4];		/* Sender IP address.  */
    unsigned char ar_tha[ETH_ALEN];	/* Target hardware address.  */
    unsigned char ar_tip[4];		/* Target IP address.  */

};

//struct packet
//{
//    const struct pcap_pkthdr *packethdr;
//    const u_char *packetptr;
//};

namespace Ui {
class Sender;
}

class Sender : public QDialog
{
    Q_OBJECT

public:
    explicit Sender(QWidget *parent = nullptr, const u_char *pkt=NULL, char* dev=NULL);
    ~Sender();


    char dev[10];
    char address[20];
    char srcaddr[20];
    char dstaddr[20];
    char srcip[20];
    char dstip[20];
    int srcport;
    int dstport;
//    char text[5000];
    Send* sendThread;
    const u_char *packet;
    int s_pks = 0;
    int s_pks_vmax = 0;

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

    char* addrToMac(u_int8_t* addr);

private slots:
    void on_Restruct_clicked();
    void on_Start_clicked();
    void on_Stop_clicked();
    void on_Cancle_clicked();
    void msgUpdate();

private:
    Ui::Sender *ui;
};

#endif // SENDER_H
