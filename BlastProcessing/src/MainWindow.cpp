#include "MainWindow.h"
#include "ui_MainWindow.h"

#include <QFontDatabase>
#include <QtDebug>
#include <QMessageBox>
#include <QFileDialog>
#include <QDir>
#include <QInputDialog>

#include "JumboMessageBox.h"

const QString VM_FILE_SETTING_KEY = "last_used_vm_disk";

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
    theProcessManager(nullptr),
    theSettings("github-mwales", "blastprocessing"),
    theSignatureFont(nullptr)
{
    ui->setupUi(this);



    fixBlastProcessingLogo();

    theProcessManager = new QemuProcessManager(this);

    connect(ui->theStartButton,    &QPushButton::clicked,
            this,                  &MainWindow::startButtonPressed);

    connect(ui->theStopButton,     &QPushButton::clicked,
            theProcessManager,     &QemuProcessManager::stopEmulator);
    connect(ui->thePauseButton,    &QPushButton::clicked,
            theProcessManager,     &QemuProcessManager::pauseEmulator);
    connect(ui->theContinueButton, &QPushButton::clicked,
            theProcessManager,     &QemuProcessManager::continueEmulator);
    connect(ui->theResetButton,    &QPushButton::clicked,
            theProcessManager,     &QemuProcessManager::resetEmulator);
    connect(ui->thePowerOffButton, &QPushButton::clicked,
            theProcessManager,     &QemuProcessManager::powerEmulatorOff);

    connect(ui->actionAboutQt,     &QAction::triggered,
            this,                  &MainWindow::helpButtonPressed);
    connect(ui->theSelectDriveAButton, &QPushButton::clicked,
            this,                  &MainWindow::selectVmButtonPressed);
    connect(ui->theScreenCapButton,&QPushButton::clicked,
            this,                  &MainWindow::screenshotButtonPressed);
    connect(ui->theSendHumanCommandButton, &QPushButton::clicked,
            this,                  &MainWindow::sendHumanCommandButtonPressed);
    connect(ui->theSaveStateButton,&QPushButton::clicked,
            this,                  &MainWindow::saveVmState);
    connect(ui->theLoadStateButton,&QPushButton::clicked,
            this,                  &MainWindow::loadVmState);

    connect(ui->theHumanCommandText, &QLineEdit::returnPressed,
            this,                    &MainWindow::sendHumanCommandButtonPressed);

    connect(theProcessManager,     &QemuProcessManager::eventReceived,
            this,                  &MainWindow::eventReceived);
    connect(theProcessManager,     &QemuProcessManager::hummanCommandResponse,
            this,                  &MainWindow::humanResponseReceived);

    if (theSettings.contains(VM_FILE_SETTING_KEY))
    {
        ui->theDriveA->setText(theSettings.value(VM_FILE_SETTING_KEY).toString());
    }
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::fixBlastProcessingLogo()
{
    int fontId = QFontDatabase::addApplicationFont(":/font/font/SEGA.TTF");
    if (-1 == fontId)
    {
        qWarning() << "Couldn't load the SEGA font";
        return;
    }
    else
    {
        qDebug() << "Loaded the SEGA font successfully";
    }

    QStringList fontList = QFontDatabase::applicationFontFamilies(fontId);
    for(auto singleFont = fontList.begin(); singleFont != fontList.end(); singleFont++)
    {
        qDebug() << "Font added: " << *singleFont;
    }

    theSignatureFont = new QFont(fontList.front(), 28);

    ui->theBlastProcessingLabel->setFont(*theSignatureFont);
}


void MainWindow::startButtonPressed()
{
    if (ui->theDriveA->text().isEmpty())
    {
        QMessageBox::critical(this, "No VM Disk Selected", "You must select a VM file before starting QEMU", QMessageBox::Ok);
        return;
    }

    theProcessManager->addDriveFile(ui->theDriveA->text());
    theProcessManager->setProcessorType("i386");
    theProcessManager->startEmulator();
}

void MainWindow::helpButtonPressed()
{
    QMessageBox::aboutQt(this, "About Qt");
}

void MainWindow::selectVmButtonPressed()
{
    QString vmFile = QFileDialog::getOpenFileName(this,
                                                  "Select VM Disk File",
                                                  QDir::homePath(),
                                                  "QEMU Disk (*.qcow2)");

    if (!vmFile.isEmpty())
    {
        qDebug() << "Selected VM File:" << vmFile;

        ui->theDriveA->setText(vmFile);

        theSettings.setValue(VM_FILE_SETTING_KEY, QVariant(vmFile));

    }

}

void MainWindow::screenshotButtonPressed()
{
    QString destName = QFileDialog::getSaveFileName(this,
                                                    "Choose screenshot filename",
                                                    QDir::homePath(),
                                                    "Portable PixMap (*.ppm)");

    if (destName.isEmpty())
    {
        // User canceled
        return;
    }

    theProcessManager->screenShot(destName);
}

void MainWindow::sendHumanCommandButtonPressed()
{
    if (!ui->theHumanCommandText->text().isEmpty())
    {
        theProcessManager->sendHumanCommandViaQmp(ui->theHumanCommandText->text());
    }
}

void MainWindow::eventReceived(QString eventText)
{
    ui->statusBar->showMessage(eventText, 3000);
}

void MainWindow::humanResponseReceived(QString rsp)
{
    if (rsp.isEmpty())
    {
        ui->statusBar->showMessage("Empty response received from human command interface", 1500);
        return;
    }

    JumboMessageBox jmb("Human Command Response", rsp, this);
    jmb.setSubtitleText("Command Response", theSignatureFont);
    jmb.exec();
}


void MainWindow::saveVmState()
{
    theProcessManager->pauseEmulator();

    bool success;
    QString stateName = QInputDialog::getText(this,
                                              "Snapshot Name Entry",
                                              "Enter a name for the snapshot",
                                              QLineEdit::Normal,
                                              "",
                                              &success);

    if (success && !stateName.isEmpty())
    {
        theProcessManager->saveEmulatorState(stateName);
    }

}

void MainWindow::loadVmState()
{
    bool success;
    QString stateName = QInputDialog::getText(this,
                                              "Snapshot Name Entry",
                                              "Enter a name for the snapshot to load",
                                              QLineEdit::Normal,
                                              "",
                                              &success);

    if (success && !stateName.isEmpty())
    {
        theProcessManager->loadEmulatorState(stateName);
    }
}
