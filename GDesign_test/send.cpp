#include <pfring.h>
#include "send.h"
#include <sys/wait.h>
#include <sys/mman.h>
#include <time.h>

using namespace std;

Send::Send(char* dev, const u_char *pkt, char* srcmac, char* dstmac,int proto, char* srcip, char* dstip, int id, int tos, int ttl, int iphlen, int tollen, int seq, int ack, int win, int tcphlen, int srcport, int dstport/*, char* text*/)
{
    char errBuf[PCAP_ERRBUF_SIZE];

    packet = pkt;
    strcpy(this->dev, dev);

    handle = pcap_open_live(this->dev, BUFSIZ, 1, 1, errBuf);

    strcpy(src_ip, srcip);
    strcpy(dst_ip, dstip);
    src_port = srcport;
    dst_port = dstport;
    this->proto = proto;
    this->id = id;
    this->tos = tos;
    this->ttl = ttl;
    this->iphlen = iphlen;
    this->tollen = tollen;
    this->seq = seq;
    this->ack = ack;
    this->win = win;
    this->tcphlen = tcphlen;

//    strcpy(newtext,text);

    struct ether_header* ethhdr;
    struct ip* iphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;
    const u_char *new_packetptr = pkt;
    char *payload;


//    memcpy(newtext, text, lens);


    ethhdr = (struct ether_header*) new_packetptr;
    strToMac(srcmac, 0);
    strToMac(dstmac, 1);
    for (int i = 0; i < 6 ; i++) {
        ethhdr->ether_shost[i] = S_mac[i];
        ethhdr->ether_dhost[i] = D_mac[i];
    }
    ethhdr->ether_type = htons(this->proto);

    new_packetptr += 14;

    iphdr = (struct ip*)new_packetptr;



    inet_aton(src_ip, &iphdr->ip_src);
    inet_aton(dst_ip, &iphdr->ip_dst);

    old_iphlen = 4*iphdr->ip_hl;
    size = 14 + ntohs(iphdr->ip_len);

    new_packetptr += 4*iphdr->ip_hl;

    iphdr->ip_id = htons(this->id);
    iphdr->ip_tos = this->tos;
    iphdr->ip_ttl = this->ttl;
    iphdr->ip_hl = this->iphlen/4;
    iphdr->ip_len = htons(this->tollen);

    switch (iphdr->ip_p)
    {
        case IPPROTO_TCP:
            /* TCP报文 */
            tcphdr = (struct tcphdr*)new_packetptr;
            tcphdr->th_sport = htons(srcport);
            tcphdr->th_dport = htons(dstport);

            tcphdr->th_seq = htonl(this->seq);
            tcphdr->th_ack = htonl(this->ack);
            tcphdr->th_win = htons(this->win);
            tcphdr->th_off = this->tcphlen/4;


//            iphdr->ip_len = htons(4*iphdr->ip_hl + 4*tcphdr->th_off +lens);

//            payload = (char *)new_packetptr + 4 * tcphdr->th_off;
//            strcpy(payload, newtext);
//            memcpy(payload, newtext, lens);
            break;

        case IPPROTO_UDP:
            /* UDP报文 */
            udphdr = (struct udphdr*)new_packetptr;
            udphdr->uh_sport = htons(srcport);
            udphdr->uh_dport = htons(dstport);

//            iphdr->ip_len = htons(4*iphdr->ip_hl + 16 +lens);

//            payload = (char *)new_packetptr + 16;
//            strcpy(payload, newtext);
//            memcpy(payload, newtext, lens);
            break;
    }


}

Send::~Send()
{
    pcap_close(handle);
//    pfring_close(pfhandle);
}

void Send::run(){
    pfring *pfhandle = pfring_open(dev, BUFSIZ, PF_RING_PROMISC);
    pfring_set_direction(pfhandle, rx_only_direction);
    pfring_enable_ring(pfhandle);
    pfring_bind(pfhandle, dev);
    int res;
    while(send_pks < 500000){
        if(pfhandle == NULL){
            qDebug() << "pfring_open";
            res = pcap_sendpacket(handle, packet, size);
        }else {
            res = pfring_send(pfhandle, (char *)packet, size, 1);

        }
        qDebug() << res;
        send_bytes += size;
        send_pks ++;
//        usleep(1);
//        nanosleep(ts, &ts);
        for (int i = 0; i < 500; i++);
    }
    pfring_close(pfhandle);
}

void Send::strToMac(char* str, int flag){
    smatch res;
    string macstr = (string) str;
    regex r("^(.*):(.*):(.*):(.*):(.*):(.*)$");
    if(flag == 0){
        if (regex_search(macstr, res, r)) {
            S_mac[0] = stoi(res[1], 0, 16);
            S_mac[1] = stoi(res[2], 0, 16);
            S_mac[2] = stoi(res[3], 0, 16);
            S_mac[3] = stoi(res[4], 0, 16);
            S_mac[4] = stoi(res[5], 0, 16);
            S_mac[5] = stoi(res[6], 0, 16);
        }
    } else{
        if (regex_search(macstr, res, r)) {
            D_mac[0] = stoi(res[1], 0, 16);
            D_mac[1] = stoi(res[2], 0, 16);
            D_mac[2] = stoi(res[3], 0, 16);
            D_mac[3] = stoi(res[4], 0, 16);
            D_mac[4] = stoi(res[5], 0, 16);
            D_mac[5] = stoi(res[6], 0, 16);
        }
    }

}
