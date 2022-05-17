#include "send.h"

#include "sender.h"
#include "ui_sender.h"
#include <string.h>
//using namespace std;
#include "alertdialog.h"
#include <time.h>
#include <QTimer>

using namespace std;

Sender::Sender(QWidget *parent, const u_char *packetptr, char* dev) :
    QDialog(parent),
    ui(new Ui::Sender)
{
    ui->setupUi(this);

    strcpy(this->dev, dev);
    struct ether_header* ethhdr;
    struct arp_hdr2* arp_header;
    struct ip* iphdr;
    struct icmp* icmphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;


    const char* payload;
    packet = packetptr;
    const u_char *new_packetptr = packetptr;

    QString load;
    char loadbuffer[20];

    // Ethernet Header
    ethhdr = (struct ether_header*) new_packetptr;
    addrToMac(ethhdr->ether_shost);
    strcpy(srcaddr, address);
    addrToMac(ethhdr->ether_dhost);
    strcpy(dstaddr, address);

    proto = ntohs(ethhdr->ether_type);

    if (ntohs(ethhdr->ether_type) == ETHERTYPE_IP) {

        new_packetptr += 14;

        iphdr = (struct ip*)new_packetptr;

        strcpy(srcip, inet_ntoa(iphdr->ip_src));
        strcpy(dstip, inet_ntoa(iphdr->ip_dst));

        id = ntohs(iphdr->ip_id);
        tos = iphdr->ip_tos;
        ttl = iphdr->ip_ttl;
        iphlen = 4*iphdr->ip_hl;
        tollen = ntohs(iphdr->ip_len);

        new_packetptr += 4*iphdr->ip_hl;
        switch (iphdr->ip_p)
        {
            case IPPROTO_TCP:
                /* TCP报文 */
                tcphdr = (struct tcphdr*)new_packetptr;
                srcport = ntohs(tcphdr->th_sport);
                dstport = ntohs(tcphdr->th_dport);
                payload = (char *)new_packetptr + 4 * tcphdr->th_off;
//                strcpy(text, payload);
//                text = payload;
                seq = ntohl(tcphdr->th_seq);
                ack = ntohl(tcphdr->th_ack);
                win = ntohs(tcphdr->th_win);
                tcphlen = 4*tcphdr->th_off;

                for(int i = 0; i < tollen - iphlen - 4 * tcphdr->th_off; i++){
                    sprintf(loadbuffer, "0x%x ", payload[i]);
                    load += loadbuffer;
                }

                break;

            case IPPROTO_UDP:
                /* UDP报文 */
                udphdr = (struct udphdr*)new_packetptr;
                srcport = ntohs(udphdr->uh_sport);
                dstport = ntohs(udphdr->uh_dport);
                payload = (char *)new_packetptr + 16;
//                strcpy(text, payload);
//                text = payload;

                for(int i = 0; i < tollen - iphlen - 16; i++){
                    sprintf(loadbuffer, "0x%x ", payload[i]);
                    load += loadbuffer;
                }


                break;
            default:
                alertDialog al;
                al.exec();
                break;
        }
    }else {
        alertDialog al;
        al.exec();
    }
    ui->Src_mac->setText(srcaddr);
    ui->Dst_mac->setText(dstaddr);
    ui->Proto->setText(QString::number(proto, 10));

    ui->Src_ip->setText(srcip);
    ui->Dst_ip->setText(dstip);
    ui->ID->setText(QString::number(id, 10));
    ui->TOS->setText(QString::number(tos, 10));
    ui->TTL->setText(QString::number(ttl, 10));
    ui->IPHlen->setText(QString::number(iphlen, 10));
    ui->TOLlen->setText(QString::number(tollen, 10));

    ui->Src_port->setText(QString::number(srcport, 10));
    ui->Dst_port->setText(QString::number(dstport, 10));
    ui->Seq->setText(QString::number(seq, 16));
    ui->Ack->setText(QString::number(ack, 16));
    ui->Win->setText(QString::number(win, 10));
    ui->TCPHlen->setText(QString::number(tcphlen, 10));

//    ui->Msg->setText(QString::fromStdString(text).toUtf8().toHex());
    ui->Msg->setText(load);


}

Sender::~Sender()
{
    delete ui;
}

char* Sender::addrToMac(u_int8_t* addr){
    /* 实现网络地址数组转为MAC地址字符串 */
    memset(address, '\0', 20);
    sprintf(address, "%02x:%02x:%02x:%02x:%02x:%02x",
            addr[0],addr[1],addr[2],addr[3],addr[4],addr[5]);
    address[strlen(address)] = '\0';
    char *p = address;
    return p;
}

void Sender:: msgUpdate()
{
    s_pks_vmax = s_pks_vmax > (sendThread->send_pks - s_pks)*10 ? s_pks_vmax : (sendThread->send_pks - s_pks)*10;
    if((sendThread->send_pks - s_pks)*10 > 1000000){
        ui->v->setText(QString("发包速率 : %1 Mpps").arg(QString::number((sendThread->send_pks - s_pks)*10/1000000, 10)));
    }else if((sendThread->send_pks - s_pks)*10 > 1000){
        ui->v->setText(QString("发包速率 : %1 Kpps").arg(QString::number((sendThread->send_pks - s_pks)*10/1000, 10)));
    }else {
        ui->v->setText(QString("发包速率 : %1 pps").arg(QString::number((sendThread->send_pks - s_pks)*10, 10)));
    }
    if(s_pks_vmax > 1000000){
        ui->v_max->setText(QString("最大发包速率 : %1 Mpps").arg(QString::number(s_pks_vmax/1000000, 10)));
    }else if(s_pks_vmax > 1000){
        ui->v_max->setText(QString("最大发包速率 : %1 Kpps").arg(QString::number(s_pks_vmax/1000, 10)));
    }else {
        ui->v_max->setText(QString("最大发包速率 : %1 pps").arg(QString::number(s_pks_vmax, 10)));
    }
    s_pks = sendThread->send_pks;

    ui->send->setText(QString("发包总数 : %1").arg(QString::number(sendThread->send_pks, 10)));
}

void Sender::on_Restruct_clicked()
{
    strcpy(srcaddr, ui->Src_mac->text().toStdString().data());
    strcpy(dstaddr, ui->Dst_mac->text().toStdString().data());
    proto = ui->Proto->text().toUInt();

    strcpy(srcip, ui->Src_ip->text().toStdString().data());
    strcpy(dstip, ui->Dst_ip->text().toStdString().data());
    id = ui->ID->text().toInt();
    tos = ui->TOS->text().toInt();
    ttl = ui->TTL->text().toInt();
    iphlen = ui->IPHlen->text().toInt();
    tollen = ui->TOLlen->text().toInt();

    seq = ui->Seq->text().toInt();
    ack = ui->Ack->text().toInt();
    win = ui->Win->text().toInt();
    tcphlen = ui->TCPHlen->text().toInt();
    srcport = ui->Src_port->text().toInt();
    dstport = ui->Dst_port->text().toInt();
//    strcpy(text, ui->Msg->toPlainText().toStdString().data());

    sendThread = new Send(dev, packet, srcaddr, dstaddr, proto, srcip, dstip, id, tos, ttl, iphlen, tollen, seq, ack, win, tcphlen, srcport, dstport);
}
void Sender::on_Start_clicked()
{
    sendThread->start();

    QTimer *timer = new QTimer;
    connect(timer,SIGNAL(timeout()),
            this,SLOT(msgUpdate()));
    timer->start(100);

}
void Sender::on_Stop_clicked()
{
    sendThread->terminate();
    sendThread->wait();
}
void Sender::on_Cancle_clicked()
{
    close();
}
