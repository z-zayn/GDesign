#ifndef SELECTDIALOG_H
#define SELECTDIALOG_H

#include <QDialog>

namespace Ui {
class SelectDialog;
}

class SelectDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SelectDialog(QWidget *parent = nullptr);
    ~SelectDialog();


private slots:
    void on_checkBoxOffline_clicked();

    void on_checkBoxSave_clicked();

    void on_OK_clicked();

    void on_Cancle_clicked();

    void on_retran_clicked();

private:
    Ui::SelectDialog *ui;
    bool offline,save,ifretran;
    char FilePath[32];
    char SavePath[32];
    char dev[15];
    char filter[64];
    char to_ip[20];
    char to_mac[20];
    char my_ip[20];
    char my_mac[20];
};

#endif // SELECTDIALOG_H
