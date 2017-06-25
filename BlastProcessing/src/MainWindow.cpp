#include "MainWindow.h"
#include "ui_MainWindow.h"

#include <QFontDatabase>
#include <QtDebug>
#include <QMessageBox>
#include <QFileDialog>
#include <QDir>
#include <QInputDialog>
#include <iostream>
#include <vector>
#include <set>

#include "JumboMessageBox.h"
#include "BlastProcessing.h"

const QString VM_FILE_SETTING_KEY = "last_used_vm_disk";

const char* IMAGE_FORMATS = "QEMU Copy-on-write (*.qcow2);;Raw (*.raw);;VMWare (*.vmdk);;VirtualBox (*.vdi);;Any (*)";

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
    theProcessManager(nullptr),
    theSettings("github-mwales", "blastprocessing"),
    theSignatureFont(nullptr)
{
    ui->setupUi(this);

    loadControls();

    applySpecialFont();

    theProcessManager = new QemuProcessManager(this);

    connect(ui->theStartButton,         &QPushButton::clicked,
            this,                       &MainWindow::startButtonPressed);

    connect(ui->theStopButton,          &QPushButton::clicked,
            theProcessManager,          &QemuProcessManager::stopEmulator);
    connect(ui->thePauseButton,         &QPushButton::clicked,
            theProcessManager,          &QemuProcessManager::pauseEmulator);
    connect(ui->theContinueButton,      &QPushButton::clicked,
            theProcessManager,          &QemuProcessManager::continueEmulator);
    connect(ui->theResetButton,         &QPushButton::clicked,
            theProcessManager,          &QemuProcessManager::resetEmulator);
    connect(ui->thePowerOffButton,      &QPushButton::clicked,
            theProcessManager,          &QemuProcessManager::powerEmulatorOff);

    connect(ui->theBlastProcButton,     &QPushButton::clicked,
            this,                       &MainWindow::startBlastProcessing);

    connect(ui->actionAboutQt,          &QAction::triggered,
            this,                       &MainWindow::helpButtonPressed);
    connect(ui->actionSave,             &QAction::triggered,
            this,                       &MainWindow::saveConfig);
    connect(ui->actionLoad,             &QAction::triggered,
            this,                       &MainWindow::loadConfig);

    connect(ui->theSelectDriveAButton,  &QPushButton::clicked,
            this,                       &MainWindow::selectDriveAPressed);
    connect(ui->theSelectDriveBButton,  &QPushButton::clicked,
            this,                       &MainWindow::selectDriveBPressed);
    connect(ui->theSelectOpticalButton, &QPushButton::clicked,
            this,                       &MainWindow::selectOpticalDrivePressed);

    connect(ui->theScreenCapButton,     &QPushButton::clicked,
            this,                       &MainWindow::screenshotButtonPressed);
    connect(ui->theSendHumanCmdButton,  &QPushButton::clicked,
            this,                       &MainWindow::sendHumanCommandButtonPressed);
    connect(ui->theSaveStateButton,     &QPushButton::clicked,
            this,                       &MainWindow::saveVmState);
    connect(ui->theLoadStateButton,     &QPushButton::clicked,
            this,                       &MainWindow::loadVmState);

    connect(ui->theHumanCommandText,    &QLineEdit::returnPressed,
            this,                       &MainWindow::sendHumanCommandButtonPressed);

    connect(theProcessManager,          &QemuProcessManager::eventReceived,
            this,                       &MainWindow::eventReceived);
    connect(theProcessManager,          &QemuProcessManager::hummanCommandResponse,
            this,                       &MainWindow::humanResponseReceived);

    if (theSettings.contains(VM_FILE_SETTING_KEY))
    {
        ui->theDriveA->setText(theSettings.value(VM_FILE_SETTING_KEY).toString());
    }

    // Connect a whole bunch of controls to the slot that fixes the port number GUI
    connect(ui->theNumPorts,       SIGNAL(valueChanged(int)),
            this,                  SLOT(updatePortNumberGui()));
    connect(ui->theVncCheckbox,    &QCheckBox::stateChanged,
            this,                  &MainWindow::updatePortNumberGui);
    connect(ui->theHmiCheckbox,    &QCheckBox::stateChanged,
            this,                  &MainWindow::updatePortNumberGui);
    connect(ui->theQmpPort,       SIGNAL(valueChanged(int)),
            this,                  SLOT(updatePortNumberGui()));

    thePortForwardControls.append({ui->thePortALabel, ui->thePortA, ui->thePortAArrow, ui->thePortADest});
    thePortForwardControls.append({ui->thePortBLabel, ui->thePortB, ui->thePortBArrow, ui->thePortBDest});
    thePortForwardControls.append({ui->thePortCLabel, ui->thePortC, ui->thePortCArrow, ui->thePortCDest});
    thePortForwardControls.append({ui->thePortDLabel, ui->thePortD, ui->thePortDArrow, ui->thePortDDest});
    thePortForwardControls.append({ui->thePortELabel, ui->thePortE, ui->thePortEArrow, ui->thePortEDest});
    thePortForwardControls.append({ui->thePortFLabel, ui->thePortF, ui->thePortFArrow, ui->thePortFDest});

    updatePortNumberGui();
}

MainWindow::~MainWindow()
{
    delete ui;

    delete theSignatureFont;
    delete theButtonFont;
}

void MainWindow::saveConfig()
{
    QString filepath = QFileDialog::getSaveFileName(this,
                                                    "Save QEMU Configuration",
                                                    QDir::homePath(),
                                                    "QEMU Config (*.qemucfg);;Any (*)");

    if (!filepath.isEmpty())
    {
        QemuConfiguration qcfg;
        readCurrentConfig(qcfg);

        if (!qcfg.saveConfiguration(filepath.toStdString()))
        {
            QMessageBox::critical(this,
                                  "Error Saving Configuration",
                                  qcfg.getErrorMessage().c_str());
        }
    }
}

void MainWindow::loadConfig()
{
    QString filepath = QFileDialog::getOpenFileName(this,
                                                    "Load QEMU Configuration",
                                                    QDir::homePath(),
                                                    "QEMU Config (*.qemucfg);;Any (*)");

    if (filepath.isEmpty())
    {
        return;
    }

    QemuConfiguration qcfg;
    if (!qcfg.loadConfiguration(filepath.toStdString()))
    {
        QMessageBox::critical(this,
                              "Error Loading Configuration",
                              qcfg.getErrorMessage().c_str());
        return;
    }

    ui->theCpuArch->setCurrentText(qcfg.getProcessorType().c_str());
    ui->theNumCpus->setValue(qcfg.getNumberOfCpus());
    ui->theNetworkAdapter->setCurrentText(qcfg.getNetworkAdapterType().c_str());
    ui->theRam->setCurrentText(QString::number(qcfg.getMemorySize()));
    ui->theDisplayAdapter->setCurrentText(qcfg.getVgaType().c_str());
    ui->theVncCheckbox->setChecked(qcfg.getVncSocketEnabled());
    ui->theHmiCheckbox->setChecked(qcfg.getHumanInterfaceSocketEnabled());
    ui->theFreeformOptions->setText(qcfg.getOtherOptions().c_str());
    ui->theDriveA->setText(qcfg.getDriveA().c_str());
    ui->theDriveAQCow2->setChecked(qcfg.getDriveAQCow2());
    ui->theDriveA->setText(qcfg.getDriveA().c_str());
    ui->theDriveAQCow2->setChecked(qcfg.getDriveAQCow2());
    ui->theOpticalDrive->setText(qcfg.getOpticalDrive().c_str());
    ui->theQmpPort->setValue(qcfg.getStartingPortNumber());

    int numUserPorts = qcfg.getNumberUserPorts();
    ui->theNumPorts->setValue(numUserPorts);
    for(int i = 0; i < numUserPorts; i++)
    {
        thePortForwardControls[i].theDesintation->setValue(qcfg.getPortForwardDestination(i));
    }

    updatePortNumberGui();

    showConfigurationWarnings(qcfg, "File Load Warnings");
}


void MainWindow::applySpecialFont()
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

    QFont* theButtonFont = new QFont(fontList.front(), 11);
    ui->theBlastProcButton->setFont(*theButtonFont);
}


void MainWindow::startButtonPressed()
{
    QemuConfiguration qemuCfg;
    QStringList warningMsgs = readCurrentConfig(qemuCfg);
    if (!warningMsgs.isEmpty())
    {
        QString msg = QString("Warnings:\n%1").arg(warningMsgs.join('\n'));
        QMessageBox::StandardButton choice = QMessageBox::warning(this,
                                                                  "QEMU Configuration Warnings",
                                                                  msg,
                                                                  QMessageBox::Ok | QMessageBox::Cancel);

        if (choice == QMessageBox::Cancel)
        {
            return;
        }
        else
        {
            qInfo() << "User overrode warnings about QEMU configuration: "
                    << warningMsgs.join(", ") << ".";
        }
    }

    theProcessManager->startEmulator(qemuCfg);
}

void MainWindow::helpButtonPressed()
{
    QMessageBox::aboutQt(this, "About Qt");
}

void MainWindow::selectDriveAPressed()
{
    QString vmFile = QFileDialog::getOpenFileName(this,
                                                  "Select VM Disk File",
                                                  QDir::homePath(),
                                                  IMAGE_FORMATS);

    if (!vmFile.isEmpty())
    {
        ui->theDriveA->setText(vmFile);
    }

}


void MainWindow::selectDriveBPressed()
{
    QString vmFile = QFileDialog::getOpenFileName(this,
                                                  "Select VM Disk File",
                                                  QDir::homePath(),
                                                  IMAGE_FORMATS);

    if (!vmFile.isEmpty())
    {
        ui->theDriveB->setText(vmFile);
    }
}

void MainWindow::selectOpticalDrivePressed()
{
    QString vmFile = QFileDialog::getOpenFileName(this,
                                                  "Select ISO Image",
                                                  QDir::homePath(),
                                                  "ISO (*.iso)");

    if (!vmFile.isEmpty())
    {
        ui->theOpticalDrive->setText(vmFile);
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

void MainWindow::updatePortNumberGui()
{
    // Assign port numbers
    int curPortNum = ui->theQmpPort->value();
    curPortNum++;

    if(ui->theHmiCheckbox->isChecked())
    {
        ui->theHmiPort->setText(QString::number(curPortNum++));
        ui->theHmiPort->show();
        ui->theHmiPort->setReadOnly(true);
        ui->theHmiPortLabel->show();
    }
    else
    {
        ui->theHmiPort->hide();
        ui->theHmiPortLabel->hide();
    }

    if(ui->theVncCheckbox->isChecked())
    {
        QString vncPortText = QString("VNC :%1").arg(curPortNum - 5900);

        ui->theVncPort->setText(vncPortText);
        ui->theVncPort->show();
        ui->theVncPort->setReadOnly(true);
        ui->theVncPortLabel->show();
    }
    else
    {
        ui->theVncPort->hide();
        ui->theVncPortLabel->hide();
    }

    // Loop will update the other 6 general purpose ports
    for(int i = 0; i < 6; i++)
    {
        struct PortForwardControls curControl = thePortForwardControls[i];
        if (ui->theNumPorts->value() >= (i + 1) )
        {
            // Port is visible
            curControl.thePortLabel->show();
            curControl.theSourcePort->setText(QString::number(curPortNum++));
            curControl.theSourcePort->show();
            curControl.theSourcePort->setReadOnly(true);
            curControl.theArrow->show();
            curControl.theDesintation->show();
        }
        else
        {
            // Port should be hidden
            curControl.thePortLabel->hide();
            curControl.theSourcePort->hide();
            curControl.theArrow->hide();
            curControl.theDesintation->hide();
        }
    }
}

void MainWindow::startBlastProcessing()
{
    QemuConfiguration qemuCfg;
    QStringList warnings = readCurrentConfig(qemuCfg);

    if (!warnings.isEmpty())
    {
        QString warningMsg = QString("Proceed with Blast Processing?\n\n%1").arg(warnings.join('\n'));

        QMessageBox::StandardButton results = QMessageBox::warning(this,
                                                                   "QEMU Configuration Warnings",
                                                                   warningMsg);

        if (results != QMessageBox::Ok)
        {
            // User canceled
            return;
        }
    }

    BlastProcessing* bp = new BlastProcessing(qemuCfg, this);
    bp->show();
}

void MainWindow::loadControls()
{
    std::set<std::string> processorList = QemuConfiguration::getQemuProcessorTypeList();
    for(auto singleArch = processorList.begin(); singleArch != processorList.end(); singleArch++)
    {
        ui->theCpuArch->addItem(QString(singleArch->c_str()));
    }

    std::set<std::string> adapterList = QemuConfiguration::getQemuNetworkAdapterTypeList();
    for(auto singleAdapter = adapterList.begin(); singleAdapter != adapterList.end(); singleAdapter++)

    {
        ui->theNetworkAdapter->addItem(QString(singleAdapter->c_str()));
    }

    std::set<std::string> ramSizeList = QemuConfiguration::getMemorySizes();
    for(auto singleSize = ramSizeList.begin(); singleSize != ramSizeList.end(); singleSize++)

    {
        ui->theRam->addItem(QString(singleSize->c_str()));
    }

    std::set<std::string> vgaList = QemuConfiguration::getVgaTypes();
    for(auto singleVga = vgaList.begin(); singleVga != vgaList.end(); singleVga++)

    {
        ui->theDisplayAdapter->addItem(QString(singleVga->c_str()));
    }


}

QStringList MainWindow::readCurrentConfig(QemuConfiguration& cfgByRef)
{
    QStringList retVal;

    cfgByRef.setDriveA(ui->theDriveA->text().toStdString(), ui->theDriveAQCow2->isChecked());
    cfgByRef.setDriveB(ui->theDriveB->text().toStdString(), ui->theDriveBQCow2->isChecked());

    cfgByRef.setOpticalDrive(ui->theOpticalDrive->text().toStdString());

    std::string proc = ui->theCpuArch->currentText().toStdString();
    std::set<std::string> defaultProcs = QemuConfiguration::getQemuProcessorTypeList();
    if (defaultProcs.find(proc) == defaultProcs.end())
    {
        retVal.append(QString("Processor %1 is not in the default list of processors").arg(proc.c_str()));
    }
    cfgByRef.setProcessorType(proc);

    std::string nic = ui->theNetworkAdapter->currentText().toStdString();
    std::set<std::string> defaultNics = QemuConfiguration::getQemuNetworkAdapterTypeList();
    if (defaultNics.find(nic) == defaultNics.end())
    {
        retVal.append(QString("Network adapter %1 is not in the default list of NICs").arg(nic.c_str()));
    }
    cfgByRef.setNetworkAdapterType(nic);

    std::string video = ui->theDisplayAdapter->currentText().toStdString();
    std::set<std::string> defaultVgas = QemuConfiguration::getVgaTypes();
    if (defaultVgas.find(video) == defaultVgas.end())
    {
        retVal.append(QString("Video adapter %1 is not in the default list of NICs").arg(video.c_str()));
    }
    cfgByRef.setVgaType(video);

    cfgByRef.enableHumanInterfaceSocket(ui->theHmiCheckbox->isChecked());
    cfgByRef.enableVncSocket(ui->theVncCheckbox->isChecked());

    cfgByRef.setOtherOptions(ui->theFreeformOptions->text().toStdString());

    cfgByRef.setMemorySize(ui->theRam->currentText().toInt());

    cfgByRef.setStartingPortNumber(ui->theQmpPort->value());

    cfgByRef.setNumberOfCpus(ui->theNumCpus->value());

    cfgByRef.setNumberUserPorts(ui->theNumPorts->value());

    for(int i = 0; i < ui->theNumPorts->value(); i++)
    {
        cfgByRef.setPortForwardDestination(i, thePortForwardControls[i].theDesintation->value());
    }

    return retVal;

}

void MainWindow::showConfigurationWarnings(QemuConfiguration & cfgByRef, QString title)
{
    std::vector<std::string> warnings = cfgByRef.getWarnings();

    if (warnings.empty())
    {
        // No warnings to show
        return;
    }

    QStringList warningList;
    for(auto singleWarn = warnings.begin(); singleWarn != warnings.end(); singleWarn++)
    {
        warningList.append(singleWarn->c_str());
    }

    QMessageBox::warning(this,
                         title,
                         warningList.join('\n'));
}
