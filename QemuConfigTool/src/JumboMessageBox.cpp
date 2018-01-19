#include "JumboMessageBox.h"
#include "ui_JumboMessageBox.h"

JumboMessageBox::JumboMessageBox(QString title, QString message, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::JumboMessageBox)
{
    ui->setupUi(this);

    setWindowTitle(title);
    ui->theText->setPlainText(message);

    ui->theSubTitle->hide();
}

JumboMessageBox::~JumboMessageBox()
{
    delete ui;
}

void JumboMessageBox::setSubtitleText(QString text, QFont* font)
{
    ui->theSubTitle->setText(text);

    if(font != nullptr)
    {
        ui->theSubTitle->setFont(*font);
    }

    ui->theSubTitle->show();
}
