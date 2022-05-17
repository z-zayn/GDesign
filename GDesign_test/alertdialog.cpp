#include "alertdialog.h"
#include "ui_alertdialog.h"

alertDialog::alertDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::alertDialog)
{
    ui->setupUi(this);
}

alertDialog::~alertDialog()
{
    delete ui;
}
