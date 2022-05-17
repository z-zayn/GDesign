#include "widget.h"
#include "ui_widget.h"
#include <QTimer>
#include <QDebug>

#include "sender.h"
#include "capture.h"


Widget::Widget(QWidget *parent, char* dev, char* filter, int offline, char* File, int ifsave, char* spath, bool if_retran, char* my_mac, char* my_ip, char* to_mac, char* to_ip) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);
    qDebug() << "mainWindow";
    strcpy(this->dev, dev);
    captureThread = new Capture(dev, filter, offline, File, ifsave, spath, if_retran, my_mac, my_ip, to_mac, to_ip);
    connect(ui->PacketsList, SIGNAL(itemClicked(QListWidgetItem*)), this, SLOT(infoUpdate()));
//    r_packets = 0;
}

Widget::~Widget()
{
    delete ui;
}

void Widget::msgUpdate()
{

    for(int i = 0;i < captureThread->keys_vec.length();i++){
        if(visited.contains(captureThread->keys_vec[i])){
                continue;
        }
        ui->PacketsList->addItem(captureThread->keys_vec[i]);
//        qDebug() << captureThread->keys_vec[i];
        visited.insert(captureThread->keys_vec[i], 1);
    }
//    if((captureThread->packets_byte - r_packets_byte)*11 > 1000000){
//        ui->v->setText(QString("收包速率 : %1 MByte/s").arg(QString::number((captureThread->packets_byte - r_packets_byte)*11/1000000, 10)));
//    }else if((captureThread->packets_byte - r_packets_byte)*11 > 1000){
//        ui->v->setText(QString("收包速率 : %1 KByte/s").arg(QString::number((captureThread->packets_byte - r_packets_byte)*11/1000, 10)));
//    }else {
//        ui->v->setText(QString("收包速率 : %1 Byte/s").arg(QString::number((captureThread->packets_byte - r_packets_byte)*11, 10)));
//    }
//    r_packets_byte = captureThread->packets_byte;

    ui->recive->setText(QString("收包总数 : %1").arg(QString::number(captureThread->packets, 10)));
    ui->drop->setText(QString("丢包总数 : %1").arg(QString::number(captureThread->drop_packets, 10)));

}

void Widget::infoUpdate()
{
    ui->PacketInfo->setPlainText(captureThread->payloadmap[ui->PacketsList->currentItem()->text()]);

}

void Widget::on_Start_clicked()
{

//    captureThread->start();
    ui->Start->setText("ll");

    QTimer *timer = new QTimer;
    connect(timer,SIGNAL(timeout()),
            this,SLOT(msgUpdate()));
    captureThread->start();//抓包线程启动
    timer->start(100);//界面每秒刷新

}


void Widget::on_Stop_clicked()
{
    captureThread->terminate();
    captureThread->wait();
    ui->Start->setText("Start");
}


void Widget::on_Send_clicked()
{
//    this_packetptr = captureThread->pktmap[ui->PacketsList->currentItem()->text()];
    captureThread->terminate();
    captureThread->wait();
    ui->Start->setText("Start");
    Sender* new_win = new Sender(0, captureThread->pktmap[ui->PacketsList->currentItem()->text()], dev);  //将类指针实例化
    new_win->show();
}
