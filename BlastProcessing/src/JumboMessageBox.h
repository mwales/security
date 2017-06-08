#ifndef JUMBOMESSAGEBOX_H
#define JUMBOMESSAGEBOX_H

#include <QDialog>

namespace Ui {
class JumboMessageBox;
}

class JumboMessageBox : public QDialog
{
    Q_OBJECT

public:
    explicit JumboMessageBox(QString title, QString message, QWidget *parent = 0);

    void setSubtitleText(QString text, QFont* font = nullptr);

    ~JumboMessageBox();

private:
    Ui::JumboMessageBox *ui;
};

#endif // JUMBOMESSAGEBOX_H
