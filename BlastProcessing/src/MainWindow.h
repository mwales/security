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
class QLabel;
class QLineEdit;
class QSpinBox;

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

    void selectDriveAPressed();

    void selectDriveBPressed();

    void selectOpticalDrivePressed();

    void screenshotButtonPressed();

    void sendHumanCommandButtonPressed();

    void eventReceived(QString eventText);

    void humanResponseReceived(QString rsp);

    void saveVmState();

    void loadVmState();

    void updatePortNumberGui();

    void startBlastProcessing();

private:

    void loadControls();

    void applySpecialFont();

    QStringList readCurrentConfig(QemuConfiguration & cfgByRef);

    void showConfigurationWarnings(QemuConfiguration & cfgByRef, QString title);

    Ui::MainWindow *ui;

    QemuProcessManager* theProcessManager;

    QSettings theSettings;

    QFont* theSignatureFont;
    QFont* theButtonFont;

    struct PortForwardControls
    {
        QLabel*    thePortLabel;
        QLineEdit* theSourcePort;
        QLabel*    theArrow;
        QSpinBox * theDesintation;
    };

    QVector<struct PortForwardControls> thePortForwardControls;

};

#endif // MAINWINDOW_H
