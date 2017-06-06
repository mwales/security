#include "MainWindow.h"
#include "ui_MainWindow.h"

#include <QFontDatabase>
#include <QtDebug>
#include <QMessageBox>
#include <QFileDialog>
#include <QDir>

#include "JumboMessageBox.h"

const QString VM_FILE_SETTING_KEY = "last_used_vm_disk";

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
    theProcessManager(nullptr),
    theSettings("github-mwales", "blastprocessing")
{
    ui->setupUi(this);



    fixBlastProcessingLogo();

    theProcessManager = new QemuProcessManager(this);

    connect(ui->theStartButton,    &QPushButton::clicked,
            this,                  &MainWindow::startButtonPressed);

    connect(ui->theStopButton,     &QPushButton::clicked,
            theProcessManager,     &QemuProcessManager::stopEmulator);
    connect(ui->theContinueButton, &QPushButton::clicked,
            theProcessManager,     &QemuProcessManager::continueEmulator);
    connect(ui->theResetButton,    &QPushButton::clicked,
            theProcessManager,     &QemuProcessManager::resetEmulator);
    connect(ui->thePowerOffButton, &QPushButton::clicked,
            theProcessManager,     &QemuProcessManager::powerEmulatorOff);

    connect(ui->theAboutQtButton,  &QPushButton::clicked,
            this,                  &MainWindow::helpButtonPressed);
    connect(ui->theSelectVmButton, &QPushButton::clicked,
            this,                  &MainWindow::selectVmButtonPressed);
    connect(ui->theScreenCapButton,&QPushButton::clicked,
            this,                  &MainWindow::screenshotButtonPressed);
    connect(ui->theSendHumanCommandButton, &QPushButton::clicked,
            this,                  &MainWindow::sendHumanCommandButtonPressed);

    connect(ui->theHumanCommandText, &QLineEdit::returnPressed,
            this,                    &MainWindow::sendHumanCommandButtonPressed);

    connect(theProcessManager,     &QemuProcessManager::eventReceived,
            this,                  &MainWindow::eventReceived);
    connect(theProcessManager,     &QemuProcessManager::hummanCommandResponse,
            this,                  &MainWindow::humanResponseReceived);

    if (theSettings.contains(VM_FILE_SETTING_KEY))
    {
        ui->theVmLineEdit->setText(theSettings.value(VM_FILE_SETTING_KEY).toString());
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

    QFont f(fontList.front(), 28);

    ui->theBlastProcessingLabel->setFont(f);
}


void MainWindow::startButtonPressed()
{
    if (ui->theVmLineEdit->text().isEmpty())
    {
        QMessageBox::critical(this, "No VM Disk Selected", "You must select a VM file before starting QEMU", QMessageBox::Ok);
        return;
    }

    theProcessManager->addDriveFile(ui->theVmLineEdit->text());
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

        ui->theVmLineEdit->setText(vmFile);

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

//    QMessageBox mb(QMessageBox::Information,
//                   "Response",
//                   "Human Command Response Received",
//                   QMessageBox::Ok,
//                   this);

//    mb.setTextFormat(Qt::RichText);
//    mb.setDetailedText(rsp);
//    mb.exec();

    JumboMessageBox jmb("Human Command Response", rsp, this);
    jmb.exec();


    //QMessageBox::information(this, "Human Command Interface Response", rsp, QMessageBox::Ok);
}
