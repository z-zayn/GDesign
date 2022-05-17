#include "capture.h"
#include "widget.h"


using namespace std;
Capture::Capture(char *dev, char* filter, int offline, char* File, int ifsave, char* spath, bool if_retran, char* my_mac, char* my_ip, char* to_mac, char* to_ip)
{
    char errBuf[PCAP_ERRBUF_SIZE];


    struct bpf_program bpf;
    bpf_u_int32 netmask;
    bpf_u_int32 srcip;


    if(offline == 0){
        // use net device
        // Get network device source IP address and netmask.
        if (pcap_lookupnet(dev, &srcip, &netmask, errBuf) == PCAP_ERROR) {
            fprintf(stderr, "pcap_lookupnet: %s\n", errBuf);
        }
        // Open the device for live capture.
        handle = pcap_open_live(dev, BUFSIZ, 1, 1, errBuf);
        if (handle == NULL) {
            fprintf(stderr, "pcap_open_live(): %s\n", errBuf);
        }

        // Convert the packet filter expression into a packet filter binary.
        if (pcap_compile(handle, &bpf, filter, 0, netmask) == PCAP_ERROR) {
            fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
        }
    }else{
        // use pcap file
        handle = pcap_open_offline(File, errBuf);
        if(handle == NULL) {
            fprintf(stderr, "pcap_open_offline(): %s\n", errBuf);
        }
        pcap_set_snaplen(handle, BUFSIZ);
        pcap_set_promisc(handle, 1);
        pcap_set_timeout(handle, 1);

        pcap_set_buffer_size(handle, 10 * 1024 * 1024);

        if (pcap_compile(handle, &bpf, filter, 0, 0) == PCAP_ERROR) {
            fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
        }
    }

    // Bind the packet filter to the libpcap handle.
    if (pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(handle));
    }

    save = ifsave;
    sprintf(savepath, "%s", spath);
    retran = if_retran;
    if(retran){
        strcpy(mymac, my_mac);
        strcpy(myip, my_ip);
        strcpy(tomac, to_mac);
        strcpy(toip, to_ip);

        strToMac(mymac, 0);
        strToMac(tomac, 1);
        }

}


Capture::~Capture()
{
    pcap_close(handle);
//    close(socketfd);
}

void Capture::get_link_header_len()
{
    int linktype;

    // Determine the datalink layer type.
    if ((linktype = pcap_datalink(handle)) == PCAP_ERROR) {
        fprintf(stderr, "pcap_datalink(): %s\n", pcap_geterr(handle));
    }

    // Set the datalink layer header size.
    switch (linktype)
    {
        case DLT_NULL:
            linkhdrlen = 4;
            break;

        case DLT_EN10MB:
            linkhdrlen = 14;
            break;

        case DLT_SLIP:
        case DLT_PPP:
            linkhdrlen = 24;
            break;

        default:
            printf("Unsupported datalink (%d)\n", linktype);
            linkhdrlen = 0;
    }
}

void Capture::packet_handler(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr)
{

    struct ether_header* ethhdr;
    struct arp_hdr* arp_header;
    struct ip* iphdr;
    struct icmp* icmphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;
    char ethhdrInfo[256];
    char iphdrInfo[256];
    char payloadBuff[256];
    char srcaddr[20];
    char dstaddr[20];
    char srcip[20];
    char dstip[20];
    const u_char *new_packetptr = packetptr;

//    uint8_t S_mac[6];
//    uint8_t D_mac[6];
    QString tmpip;
    QString tmpippayload;

    // copy the packet
    u_char* pk = new u_char [packethdr->caplen];
    memcpy(pk, packetptr, packethdr->caplen);

    if(retran){
        // retran
//        sendto(socketfd, packetptr, packethdr->caplen, 0, (struct sockaddr *) &addr, sizeof(addr));
        u_char* re_pk = new u_char [packethdr->caplen];
        memcpy(re_pk, packetptr, packethdr->caplen);

        const u_char* edit_pk = re_pk;

        ethhdr = (struct ether_header*) edit_pk;
        for (int i = 0; i < 6 ; i++) {
            ethhdr->ether_shost[i] = S_mac[i];
            ethhdr->ether_dhost[i] = D_mac[i];
        }

        edit_pk += 14;

        iphdr = (struct ip*) edit_pk;

        inet_aton(myip, &iphdr->ip_src);
        inet_aton(toip, &iphdr->ip_dst);

        int res = pcap_inject(handle, re_pk, packethdr->caplen);
        qDebug() << res;

    }

    char arpinfo[256];

    if(save == 1){
        // 保存文件
        save_packet(packethdr, packetptr);
    }

//    packets_byte += packethdr->caplen;
    // Ethernet Header
    ethhdr = (struct ether_header*) new_packetptr;
    // 处理Mac地址
    addrToMac(ethhdr->ether_shost);
    strcpy(srcaddr, address);
    addrToMac(ethhdr->ether_dhost);
    strcpy(dstaddr, address);
    /* 写入以太网帧头部信息 */
    sprintf(ethhdrInfo, "Mac:\n\t%s -> %s", srcaddr, dstaddr);
    tmpippayload += ethhdrInfo;
    tmpippayload += "\n";
    /* 判断包的类型 */
    if (ntohs(ethhdr->ether_type) == ETHERTYPE_IP) {
        /* IP包 */
        // Skip the datalink layer header and get the IP header fields.
        new_packetptr += linkhdrlen;
        iphdr = (struct ip*)new_packetptr;
        /* 网络字节 to 点分十进制 */

        strcpy(srcip, inet_ntoa(iphdr->ip_src));
        strcpy(dstip, inet_ntoa(iphdr->ip_dst));
        sprintf(iphdrInfo, "%s -> %s \t ID:%d TOS:0x%x, TTL:%d IpHeaderLen:%d TotalLen:%d",
                srcip, dstip, ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
                4*iphdr->ip_hl, ntohs(iphdr->ip_len));
        tmpip += iphdrInfo;

        sprintf(payloadBuff, "IP:\n\t%s -> %s\n\tID:%d\n\tTOS:0x%x\n\tTTL:%d\n\tIpHeaderLen:%d\n\tTotalLen:%d\n",
            srcip, dstip, ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
            4*iphdr->ip_hl, ntohs(iphdr->ip_len));
        tmpippayload += payloadBuff;

        // Advance to the transport layer header then parse and display
        // the fields based on the type of hearder: tcp, udp or icmp.
        new_packetptr += 4*iphdr->ip_hl;
        switch (iphdr->ip_p)
        {
            case IPPROTO_TCP:

                /* TCP报文 */
                tcphdr = (struct tcphdr*)new_packetptr;
                sprintf(payloadBuff,"TCP:\n\t%s:%d -> %s:%d\n", srcip, ntohs(tcphdr->th_sport),
                       dstip, ntohs(tcphdr->th_dport));
                tmpippayload += payloadBuff;

                sprintf(payloadBuff,"\t%c%c%c%c%c%c\n\tSeq: 0x%x\n\tAck: 0x%x\n\tWin: 0x%x\n\tTcpHeaderLen: %d\n",
                        /*  */
                       (tcphdr->th_flags & TH_URG ? 'U' : '*'),
                       (tcphdr->th_flags & TH_ACK ? 'A' : '*'),
                       (tcphdr->th_flags & TH_PUSH ? 'P' : '*'),
                       (tcphdr->th_flags & TH_RST ? 'R' : '*'),
                       (tcphdr->th_flags & TH_SYN ? 'S' : '*'),
                       (tcphdr->th_flags & TH_FIN ? 'F' : '*'),
                       ntohl(tcphdr->th_seq), ntohl(tcphdr->th_ack),
                       ntohs(tcphdr->th_win), 4*tcphdr->th_off);
                tmpippayload += payloadBuff;

                if(ntohs(tcphdr->th_dport) == 80) {
                    const char* payload = (char *)new_packetptr + 4 * tcphdr->th_off;
                    http_handler(payload, REQUEST);
                }else if(ntohs(tcphdr->th_sport) == 80) {
                    const char* payload = (char *)new_packetptr + 4 * tcphdr->th_off;
                    http_handler(payload, RESPONSE);
                }

//                packets += 1;
                break;

            case IPPROTO_UDP:
                /* UDP报文 */
                udphdr = (struct udphdr*)new_packetptr;
                sprintf(payloadBuff,"UDP:\n\t%s:%d -> %s:%d\n", srcip, ntohs(udphdr->uh_sport),
                       dstip, ntohs(udphdr->uh_dport));

                tmpippayload += payloadBuff;

//                packets += 1;
                break;

            case IPPROTO_ICMP:
                /* ICMP报文 */
                icmphdr = (struct icmp*)new_packetptr;
                sprintf(payloadBuff,"ICMP:\n\t%s -> %s\n", srcip, dstip);
                tmpippayload += payloadBuff;

                sprintf(payloadBuff,"Type:%d\n\tCode:%d\n\tID:%d\n\tSeq:%d\n", icmphdr->icmp_type, icmphdr->icmp_code,
                       ntohs(icmphdr->icmp_hun.ih_idseq.icd_id), ntohs(icmphdr->icmp_hun.ih_idseq.icd_seq));
                tmpippayload += payloadBuff;

//                packets += 1;
                break;
        }
    } else if (ntohs(ethhdr->ether_type) == ETHERTYPE_ARP) {
        /* ARP */
        arp_header = (struct arp_hdr*)new_packetptr;
        sprintf(ethhdrInfo, "Mac:%s -> %s", srcaddr, dstaddr);
        tmpip += ethhdrInfo;
        sprintf(arpinfo, "ARP:\n\tOperation: %s\n", (ntohs(arp_header->ar_op) == 1)?"ARP_REQUEST":"ARP_REPLY");

        tmpippayload += arpinfo;

        sprintf(arpinfo, "\tSource MAC:%02x:%02x:%02x:%02x:%02x:%02x\n",
               arp_header->ar_sha[0], arp_header->ar_sha[1],
               arp_header->ar_sha[2], arp_header->ar_sha[3],
               arp_header->ar_sha[4], arp_header->ar_sha[5]);

        tmpippayload += arpinfo;

        sprintf(arpinfo, "\tSource IP:%d.%d.%d.%d\n",
               arp_header->ar_sip[0], arp_header->ar_sip[1],
               arp_header->ar_sip[2], arp_header->ar_sip[3]);

        tmpippayload += arpinfo;

        sprintf(arpinfo, "\tDestination MAC:%02x:%02x:%02x:%02x:%02x:%02x\n",
               arp_header->ar_tha[0], arp_header->ar_tha[1],
               arp_header->ar_tha[2], arp_header->ar_tha[3],
               arp_header->ar_tha[4], arp_header->ar_tha[5]);
        tmpippayload += arpinfo;
        sprintf(arpinfo, "\tDestination IP:%d.%d.%d.%d\n",
               arp_header->ar_tip[0], arp_header->ar_tip[1],
               arp_header->ar_tip[2], arp_header->ar_tip[3]);
        tmpippayload += arpinfo;

//        packets += 1;
    }

    tmpippayload += tmphttp;

    ipInfo = tmpip;
    ippayloadinfo = tmpippayload;

    if(!payloadmap.contains(ipInfo)){
        payloadmap.insert(ipInfo, ippayloadinfo);
        keys_vec.append(ipInfo);
    }

    if(!pktmap.contains(ipInfo)){
        pktmap.insert(ipInfo, pk);
    }



}


void Capture::http_handler(const char* payloadhdr, int flag){

    tmphttp = "";
    char httpinfo[1024];
    /* HTTP协议分析 */
    if (flag == REQUEST) {
        string version;
        string method;
        string url = "";
        string host;
        string cookie;
        string usrAgent;
        string path;

        string data = (string) payloadhdr;
        smatch res;
        // pattern
        regex r_proto("^(.*?)\\s(/.*)\\s(HTTP.*)\r\n");
        if (regex_search(data, res, r_proto)) {
            method = res[1];
            path = res[2];
            version = res[3];
        }else{
            /* Doesn't contain HTTP Request Header*/
            return;
        }
        regex r_host("Host:\\s+(.*)\r\n");
        if (regex_search(data, res, r_host)) {
            host = res[1];
        }
        regex r_usr("User-Agent:\\s+(.*)\r\n");
        if (regex_search(data, res, r_usr)) {
            usrAgent = res[1];
        }
        regex r_cookie("Cookie:\\s+(.*)\r\n");
        if (regex_search(data, res, r_cookie)) {
            cookie = res[1];
        }
        url.append(host);
        url.append(path);
        tmphttp += "\n**********HTTP REQUEST HEADER**********\n";
        sprintf(httpinfo, "HTTP Version:%s\nMethod:%s\nURL:%s\nHost:%s\nUser-Agent:%s\nCookie:%s\n",
               version.c_str(),method.c_str(), url.c_str(), host.c_str(), usrAgent.c_str(), cookie.c_str());
        tmphttp += httpinfo;
        tmphttp += "********HTTP REQUEST HEADER END********\n\n";
    } else if (flag == RESPONSE) {
        string version;
        string status_code;
        string status_str;

        string data = (string) payloadhdr;
        smatch res;
        regex r_status("^(HTTP/\\S*?)\\s(\\S*)\\s+(.*)\r\n");
        if (regex_search(data, res, r_status)) {
            version = res[1];
            status_code = res[2];
            status_str = res[3];
        }else{
            /* Doesn't contain HTTP Response Header*/
            return;
        }

        tmphttp += "\n**********HTTP RESPONSE HEADER**********\n";

        sprintf(httpinfo, "HTTP Version:%s\nStatus:%s %s\n",
               version.c_str(),status_code.c_str(), status_str.c_str());

        tmphttp += httpinfo;

        tmphttp += "********HTTP RESPONSE HEADER END********\n\n";
    }
}


void Capture::save_packet(const struct pcap_pkthdr *packethdr, const u_char *packetptr){
    /* 保存包 */
    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_dumper_t *p = NULL;
    p = pcap_dump_open_append(handle, savepath);
    if(p == NULL){
        fprintf(stderr, "pcap_dump_open_append(): %s\n", errBuf);
    }
    pcap_dump((u_char*) p, packethdr, packetptr);
    pcap_dump_close(p);
    printf("Save this packet successfully!\n");
}

char* Capture::addrToMac(u_int8_t* addr){
    /* 实现网络地址数组转为MAC地址字符串 */
    memset(address, '\0', 20);
    sprintf(address, "%02x:%02x:%02x:%02x:%02x:%02x",
            addr[0],addr[1],addr[2],addr[3],addr[4],addr[5]);
    address[strlen(address)] = '\0';
    char *p = address;
    return p;
}

void Capture::run()
{
    qDebug() << "thread init!";
    struct pcap_stat stats;
    get_link_header_len();
    while((res = pcap_next_ex(handle,&pcap_pkthdr,&packet_content)) >= 0)
        /* 注册回调函数，循环捕获数据包 */
    {
        qDebug()<<"thread is running";
        if(res == 0)
        {
            continue;
        }
        packet_handler((u_char*)NULL, pcap_pkthdr, packet_content);
        pcap_stats(handle, &stats);

        packets = stats.ps_recv;
        drop_packets = stats.ps_drop;
    }

}
void Capture::strToMac(char* str, int flag){
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
