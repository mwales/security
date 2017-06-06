#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSettings>
#include "QemuProcessManager.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

public slots:

    void startButtonPressed();

    void helpButtonPressed();

    void selectVmButtonPressed();

    void screenshotButtonPressed();

    void sendHumanCommandButtonPressed();

    void eventReceived(QString eventText);

    void humanResponseReceived(QString rsp);

private:

    void fixBlastProcessingLogo();

    Ui::MainWindow *ui;

    QemuProcessManager* theProcessManager;

    QSettings theSettings;
};

#endif // MAINWINDOW_H
