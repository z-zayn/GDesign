#ifndef ALERTDIALOG_H
#define ALERTDIALOG_H

#include <QDialog>

namespace Ui {
class alertDialog;
}

class alertDialog : public QDialog
{
    Q_OBJECT

public:
    explicit alertDialog(QWidget *parent = nullptr);
    ~alertDialog();

private:
    Ui::alertDialog *ui;
};

#endif // ALERTDIALOG_H
