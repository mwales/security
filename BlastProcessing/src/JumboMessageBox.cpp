#include "JumboMessageBox.h"
#include "ui_JumboMessageBox.h"

JumboMessageBox::JumboMessageBox(QString title, QString message, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::JumboMessageBox)
{
    ui->setupUi(this);

    setWindowTitle(title);
    ui->theText->setPlainText(message);
}

JumboMessageBox::~JumboMessageBox()
{
    delete ui;
}
