#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QMap>
#include <time.h>
#include "capture.h"

namespace Ui {
class Widget;
}

class Widget : public QWidget
{
    Q_OBJECT

public:
    explicit Widget(QWidget *parent = nullptr, char* dev = NULL, char* filter = NULL, int offline = 0, char* File = NULL, int ifsave = 0, char* spath = NULL, bool if_retran=false, char* my_mac=NULL, char* my_ip=NULL, char* to_mac=NULL, char* to_ip=NULL);
    ~Widget();



private slots:
    void msgUpdate();
    void infoUpdate();
    void on_Start_clicked();
    void on_Stop_clicked();
    void on_Send_clicked();


private:
    Ui::Widget *ui;
    Capture* captureThread;
    QHash<QString, int> visited;
//    long long r_packets=0;
    long long r_packets_byte=0;

    QString srcmac;
    QString dstmac;
    QString srcip;
    QString dstip;
    QString srcport;
    QString dstport;
    QString text;
    char dev[10];


    const u_char *this_packetptr;


};

#endif // WIDGET_H
