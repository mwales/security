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

    void selectVmButtonPressed();

    void screenshotButtonPressed();

    void sendHumanCommandButtonPressed();

    void eventReceived(QString eventText);

    void humanResponseReceived(QString rsp);

    void saveVmState();

    void loadVmState();

    void updatePortNumberGui();

private:

    void loadControls();

    void fixBlastProcessingLogo();

    QStringList readCurrentConfig(QemuConfiguration & cfgByRef);

    Ui::MainWindow *ui;

    QemuProcessManager* theProcessManager;

    QSettings theSettings;

    QFont* theSignatureFont;

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
