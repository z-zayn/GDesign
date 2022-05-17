#include "selectdialog.h"
#include "ui_selectdialog.h"
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
#include <QDebug>
#include "widget.h"

SelectDialog::SelectDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SelectDialog)
{
    ui->setupUi(this);

    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
    char errBuf[PCAP_ERRBUF_SIZE];
    /* 获取当前计算机的所有网络设备 */
    if (pcap_findalldevs(&alldevs, errBuf) == -1) {
        qDebug()<<"1!";

        ui->devList->insertItem(0,"");
        qDebug()<<"未找到设备，请确认此程序在root权限下运行!";
    }
    for(d=alldevs; d; d=d->next) {
//        qDebug()<<QString(d->name);
        ui->devList->insertItem(i++,d->name);
    }
    pcap_freealldevs(alldevs);
    offline = save = ifretran = false;
}

SelectDialog::~SelectDialog()
{
    delete ui;
}


void SelectDialog::on_checkBoxOffline_clicked()
{
    offline = true;

}

void SelectDialog::on_checkBoxSave_clicked()
{
    save = true;

}

void SelectDialog::on_retran_clicked()
{
    ifretran = true;
}

void SelectDialog::on_OK_clicked()
{
    QString boolExp;
    int flag = false;

    if(!ui->filter->text().isEmpty()){
        boolExp += ui->filter->text();
        flag = true;
    }

//    qDebug() << boolExp;
    if(offline&&!ui->FilePath->text().isEmpty()){
        strcpy(FilePath, (ui->FilePath->text().toStdString().data()));
        qDebug() << FilePath;
    }else {
        qDebug() << "路径不存在";
    }
    if(save&&!ui->savepath->text().isEmpty()){
        strcpy(SavePath, (ui->savepath->text().toStdString().data()));
        qDebug() << SavePath;
    }else {
        qDebug() << "路径不存在";
    }

    if(ifretran){
        strcpy(to_ip, ui->to_Ip->text().toStdString().data());
        strcpy(to_mac, ui->to_Mac->text().toStdString().data());
        strcpy(my_ip, ui->my_Ip->text().toStdString().data());
        strcpy(my_mac, ui->my_Mac->text().toStdString().data());

        if(flag){
            boolExp += " and not dst net ";
            boolExp += ui->to_Ip->text();
        }else{
            boolExp += "not dst net ";
            boolExp += ui->to_Ip->text();
        }

    }

    strcpy(filter, (boolExp.toStdString().data()));

    qDebug() << boolExp;

    strcpy(dev, ui->devList->currentItem()->text().toStdString().data());


    Widget* new_win = new Widget(0, dev, filter, offline, FilePath, save, SavePath, ifretran, my_mac, my_ip, to_mac, to_ip);  //将类指针实例化
    new_win->show();


}

void SelectDialog::on_Cancle_clicked()
{
    close();
}
