#include "widget.h"
#include "selectdialog.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
//    Widget w;
//    w.show();
    SelectDialog sd;
    sd.show();

    return a.exec();
}
