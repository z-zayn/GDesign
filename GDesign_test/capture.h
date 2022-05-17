#ifndef CAPTURE_H
#define CAPTURE_H

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
#include <sys/socket.h>
#include <sys/types.h>

#include <regex>
#include <regex.h>

#include <QMap>
#include <QThread>
#include <QDebug>



#define REQUEST 0
#define RESPONSE 1

struct arp_hdr
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

struct packet
{
    const struct pcap_pkthdr *packethdr;
    const u_char *packetptr;
};

struct ipValue
{
    QString sIP;
    QString dIP;
    QString kind;
    int count;
};

class Capture : public QThread
{
public:
    Capture(char* dev, char* filter, int offline, char* File, int ifsave, char* spath, bool if_retran, char* my_mac=NULL, char* my_ip=NULL, char* to_mac=NULL, char* to_ip=NULL);
    ~Capture();
    long long packets = 0;
    long long drop_packets = 0;
    long long packets_byte = 0;
    pcap_t *handle;
    int linkhdrlen;
    int save;
    char savepath[32];
    char address[20];
    int res;
    bool retran=false;
    char tomac[20];
    char toip[20];
    char mymac[20];
    char myip[20];
    uint8_t S_mac[6];
    uint8_t D_mac[6];



    struct pcap_pkthdr *pcap_pkthdr;
    const u_char *packet_content;
//    const u_char *packetptr;
    QString ipInfo;
    QString ippayloadinfo;
    QString tmphttp;

    QMap<QString, const u_char *> pktmap;
    QMap<QString, QString> payloadmap;

    QVector<QString> keys_vec;

    void get_link_header_len();
    void packet_handler(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr);
    void http_handler(const char* payloadhdr, int flag);
    void save_packet(const struct pcap_pkthdr *packethdr, const u_char *packetptr);
    char* addrToMac(u_int8_t* addr);
    void strToMac(char* str, int flag);

protected:
    void run();
signals:
    void done(void);
};



#endif // CAPTURE_H
