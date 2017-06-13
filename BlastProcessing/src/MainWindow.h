#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSettings>
#include "QemuProcessManager.h"
#include "QemuConfiguration.h"

namespace Ui {
class MainWindow;
}

class QFont;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

public slots:
    void saveConfig();

    void loadConfig();

    void startButtonPressed();

    void helpButtonPressed();

    void selectVmButtonPressed();

    void screenshotButtonPressed();

    void sendHumanCommandButtonPressed();

    void eventReceived(QString eventText);

    void humanResponseReceived(QString rsp);

    void saveVmState();

    void loadVmState();

private:

    void loadControls();

    void fixBlastProcessingLogo();

    QStringList readCurrentConfig(QemuConfiguration & cfgByRef);

    Ui::MainWindow *ui;

    QemuProcessManager* theProcessManager;

    QSettings theSettings;

    QFont* theSignatureFont;


};

#endif // MAINWINDOW_H
