#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
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

private:

    void fixBlastProcessingLogo();

    Ui::MainWindow *ui;

    QemuProcessManager* theProcessManager;
};

#endif // MAINWINDOW_H
