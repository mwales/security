#include "BlastProcessing.h"
#include "ui_BlastProcessing.h"

#include <QThreadPool>
#include <QtDebug>
#include <QProgressDialog>
#include <QCloseEvent>
#include <QFileDialog>
#include <QFile>
#include <QMessageBox>

#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QProgressBar>
#include <QLineEdit>


#include "QemuConfiguration.h"
#include "QemuRunner.h"

const QString PRE_COMMAND_KEY =         "PRE_COMMAND";
const QString PERI_COMMAND_KEY =        "PERI_COMMAND";
const QString USE_QEMU_KEY =            "USE_QEMU";
const QString QEMU_CONFIG_FILE_KEY =    "QEMU_CONFIG_FILE";
const QString QEMU_SNAPSHOT_NAME_KEY =  "QEMU_SNAPSHOT";
const QString SEND_KEYSTROKES_KEY =     "QEMU_USE_KEYSTROKES";
const QString KEYSTROKE_VALUES_KEY =    "KEYSTROKE_VALUES";
const QString POST_COMMAND_KEY =        "POST_COMMAND";
const QString NUM_INSTANCES =           "NUM_INSTANCES";
const QString TIMEOUT_KEY =             "TIMEOUT";

const int NUM_RUNNER_UI_CONTROLS = 25;

BlastProcessing::BlastProcessing(QemuConfiguration const & cfg,
                                 QString theConfigFile,
                                 QWidget *parent) :
    QDialog(parent),
    ui(new Ui::BlastProcessing),
    theCfg(cfg),
    theStoredConfigValid(true),
    theNumInstancesToRun(0)
{
    ui->setupUi(this);

    ui->theQemuConfigFile->setText(theConfigFile);

    connect(ui->theStartButton,       &QPushButton::clicked,
            this,                     &BlastProcessing::startButtonPressed);
    connect(ui->theStopButton,        &QPushButton::clicked,
            this,                     &BlastProcessing::stopButtonPressed);
    connect(ui->theSaveButton,        &QPushButton::clicked,
            this,                     &BlastProcessing::saveButtonPressed);
    connect(ui->theLoadButton,        &QPushButton::clicked,
            this,                     &BlastProcessing::loadButtonPressed);

    connect(&theSignalMapper,         SIGNAL(mapped(QObject*)),
            this,                     SLOT(runnerStopped(QObject*)));

    connect(ui->theNumInstances,      SIGNAL(valueChanged(int)),
            this,                     SLOT(setNumInstancesUpdated(int)));

    connect(ui->theQemuConfigFile,    &QLineEdit::textChanged,
            this,                     &BlastProcessing::invalidateConfig);

    createProgressControls();


}

BlastProcessing::~BlastProcessing()
{
    stopThreadsAndWait();

    delete ui;
}

void BlastProcessing::startButtonPressed()
{
    theNumInstancesToRun = ui->theNumInstances->value();

    for(int i = 0; i < theNumInstancesToRun; i++)
    {
        spawnRunner(i);
    }

    setNumRunnerProgressToShow(theNumInstancesToRun);
}

void  BlastProcessing::closeEvent(QCloseEvent * ev)
{
    stopThreadsAndWait();
    ev->accept();
}

void BlastProcessing::stopButtonPressed()
{
    for(auto singleRunner : theRunners)
    {
        singleRunner.second.first->stopTests();
    }
}

void BlastProcessing::runnerStopped(QObject* stoppedRunnerQO)
{
    QemuRunner* stoppedRunner = dynamic_cast<QemuRunner*>(stoppedRunnerQO);

    if (!stoppedRunner)
    {
        qDebug() << "Invalid runner object called " << __PRETTY_FUNCTION__;
        return;
    }

    for(auto singleRunner : theRunners)
    {
        if (singleRunner.second.first == stoppedRunner)
        {
            qDebug() << "Runner" << stoppedRunner->getInstanceId() << "stopped";

            delete stoppedRunner;

            // I want to delete the thread here, but I always get a thread deleted while running
            // error...

            theRunners.erase(singleRunner.first);
            return;
        }
    }

    qWarning() << "Runner" << stoppedRunner->getInstanceId()
               << "stopped, but we don't have record of it starting";

}

void BlastProcessing::stopThreadsAndWait()
{
    theNumInstancesToRun = 0;

    bool showDialogOnce = true;
    QProgressDialog progressDialog;
    while(!theRunners.empty())
    {
        stopButtonPressed();

        // We pop a dialog up if we have to wait for threads to finish.  It has a cancel button,
        // I should probably make a custom dialog that just has a waiting animation that the user
        // can't cancel
        if (showDialogOnce)
        {
            progressDialog.setWindowModality(Qt::WindowModal);
            progressDialog.setAutoClose(true);
            progressDialog.setMinimum(0);
            progressDialog.setMaximum(0);
            progressDialog.setLabelText("Wait for runners to finish...");
            progressDialog.setWindowTitle("Please wait");
            progressDialog.show();
            showDialogOnce = false;
        }

        // Since the threads will call our slots when they are done, need to process slot calls
        QCoreApplication::processEvents(QEventLoop::AllEvents,1000);
        QThread::msleep(200);
    }
}

void BlastProcessing::setNumInstancesUpdated(int numProcesses)
{
    if (theNumInstancesToRun == 0)
    {
        // Ignore the spin box unless their are processes already running
        return;
    }

    if (numProcesses < theNumInstancesToRun)
    {
        // Dropped the number of cores to use
        while(numProcesses < theNumInstancesToRun)
        {
            qDebug() << "Stopping an instance";
            theRunners[theNumInstancesToRun-1].first->stopTests();
            theNumInstancesToRun--;
        }
    }
    else
    {
        // Dropped the number of cores to use
        while(numProcesses > theNumInstancesToRun)
        {
            qDebug() << "Stopping an instance";
            spawnRunner(theNumInstancesToRun);
            theNumInstancesToRun++;
        }
    }

    setNumRunnerProgressToShow(theNumInstancesToRun);
}

void BlastProcessing::spawnRunner(int instanceId)
{
    QemuRunner* runner = new QemuRunner(instanceId, theCfg);
    QThread* runnerThread = new QThread();
    runner->moveToThread(runnerThread);

    qDebug() << "RunnerThreaed = " << runnerThread;

    connect(runner,       &QemuRunner::runnerStopped,
            this,         &BlastProcessing::runnerStopped);
    connect(runnerThread, &QThread::started,
            runner,       &QemuRunner::runnerThreadStart);



    theSignalMapper.setMapping(runnerThread, runner);

    connect(runnerThread,     SIGNAL(finished()),
            &theSignalMapper, SLOT(map()));

    runner->setScripts(ui->thePreProcess->text(),
                       ui->thePeriProcess->text(),
                       ui->thePostProcess->text());
    runner->setTimeout(ui->theTimeoutSecs->value());

    // Connect GUI elements
    if (instanceId < NUM_RUNNER_UI_CONTROLS)
    {
        struct BlastProcessing::ProgressControls pc = theRunnerStatusUi[instanceId];
        connect(runner,          &QemuRunner::testProgress,
                pc.theProgress,  &QProgressBar::setValue);
        connect(runner,          &QemuRunner::testComplete,
                pc.theEdit,      &QLineEdit::setText);
    }

    qDebug() << "Blast Processing Thread = " << QThread::currentThread();
    runnerThread->start();

    theRunners[instanceId] = std::make_pair(runner, runnerThread);
}

void BlastProcessing::createProgressControls()
{
    theStatusLayout = new QVBoxLayout();
    ui->theRunnerStatusBox->setLayout(theStatusLayout);

    for(int i = 0; i < NUM_RUNNER_UI_CONTROLS; i++)
    {
        struct BlastProcessing::ProgressControls pc;
        pc.theId = new QLabel(QString("ID #%1:").arg(i+1));
        pc.theProgress = new QProgressBar();
        pc.theProgress->setMinimum(0);
        pc.theProgress->setMaximum(300);
        pc.theEdit = new QLineEdit("starting...");
        pc.theEdit->setReadOnly(true);
        pc.theLayout = new QHBoxLayout();
        pc.theLayout->addWidget(pc.theId);
        pc.theLayout->addWidget(pc.theProgress);
        pc.theLayout->addWidget(pc.theEdit);

        theStatusLayout->addLayout(pc.theLayout);

        theRunnerStatusUi.push_back(pc);
    }

    theMoreNotShownLabel = new QLabel("More status not shown");
    theStatusLayout->addWidget(theMoreNotShownLabel);

    setNumRunnerProgressToShow(0);
}

void BlastProcessing::setNumRunnerProgressToShow(int count)
{
    for(int i = 0; i < NUM_RUNNER_UI_CONTROLS; i++)
    {
        struct BlastProcessing::ProgressControls pc = theRunnerStatusUi[i];

        bool curShown;
        if (i < count)
        {
            // Show this control
            curShown = true;
        }
        else
        {
            // Do not show control
            curShown = false;
        }

        pc.theId->setVisible(curShown);
        pc.theProgress->setVisible(curShown);
        pc.theEdit->setVisible(curShown);
    }

    if (count <= NUM_RUNNER_UI_CONTROLS)
    {
        theMoreNotShownLabel->setVisible(false);
    }
    else
    {
        theMoreNotShownLabel->setVisible(true);
        theMoreNotShownLabel->setText(QString("Status for %1 more runners not shown...").arg(count - NUM_RUNNER_UI_CONTROLS));
    }
}


void BlastProcessing::saveGuiConfigFile(QString filename)
{
    QFile outputFile(filename);
    if (!outputFile.open(QIODevice::WriteOnly))
    {
        QString errMessage = "Error opening file ";
        errMessage += filename;
        errMessage += " to write BP configuration to:";
        errMessage += outputFile.errorString();
        qWarning() << errMessage;
        QMessageBox::warning(this, "Error saving BP Config", errMessage);
        return;
    }

    QMap<QString,QString> configValues;
    configValues[PRE_COMMAND_KEY] = ui->thePreProcess->text();
    configValues[PERI_COMMAND_KEY] = ui->thePeriProcess->text();
    configValues[POST_COMMAND_KEY] = ui->thePostProcess->text();
    configValues[USE_QEMU_KEY] = (ui->theUseQemuCb->isChecked() ? "TRUE" : "FALSE");
    configValues[QEMU_CONFIG_FILE_KEY] = ui->theQemuConfigFile->text();
    configValues[QEMU_SNAPSHOT_NAME_KEY] = ui->theQemuSnapshot->text();
    configValues[SEND_KEYSTROKES_KEY] = (ui->theQemuUseKeysCb->isChecked() ? "TRUE" : "FALSE");
    configValues[KEYSTROKE_VALUES_KEY] = ui->theKeystrokeValues->text();
    configValues[NUM_INSTANCES] = QString::number(ui->theNumInstances->value());
    configValues[TIMEOUT_KEY] = QString::number(ui->theTimeoutSecs->value());

    foreach(QString keyVal , configValues.keys())
    {
        QString textToWrite = QString("%1=%2\n").arg(keyVal).arg(configValues[keyVal]);

        if (!outputFile.write(textToWrite.toLocal8Bit()))
        {
            QString errMessage = "Error writing BP config to file";
            errMessage += filename;
            errMessage += ": ";
            errMessage += outputFile.errorString();

            qWarning() << errMessage;

            QMessageBox::warning(this, "Error saving BP Config", errMessage);

            outputFile.close();
            return;
        }
    }

    outputFile.close();
    qDebug() << "Saved BP config" << filename << "successfully";
}

void BlastProcessing::loadGuiConfigFile(QString filename)
{
    QFile cfgFile(filename);
    if (!cfgFile.open(QIODevice::ReadOnly))
    {
        QString errMessage = "Error opening config file ";
        errMessage += filename;
        errMessage += ": ";
        errMessage += cfgFile.errorString();

        qWarning() << errMessage;
        QMessageBox::critical(this,
                              "File Open Error",
                              errMessage);
        return;
    }

    QString configContents = cfgFile.readAll();
    QStringList cfgLines = configContents.split('\n', QString::SkipEmptyParts);
    QMap<QString, QString> nvPairs;
    foreach(QString singleLine, cfgLines)
    {
        QStringList lineData = singleLine.split('=', QString::SkipEmptyParts);
        if (lineData.length() != 2)
        {
            qWarning() << "BP parse failure, expect 2 terms: " << singleLine;
            continue;
        }

        nvPairs[lineData[0].trimmed()]=lineData[1].trimmed();
    }

    ui->thePreProcess->setText(nvPairs.value(PRE_COMMAND_KEY, ""));
    ui->thePeriProcess->setText(nvPairs.value(PERI_COMMAND_KEY, ""));
    ui->theUseQemuCb->setChecked(nvPairs.value(USE_QEMU_KEY, "FALSE") == "TRUE");
    ui->theQemuConfigFile->setText(nvPairs.value(QEMU_CONFIG_FILE_KEY, ""));
    ui->theQemuSnapshot->setText(nvPairs.value(QEMU_SNAPSHOT_NAME_KEY, ""));
    ui->theQemuUseKeysCb->setChecked(nvPairs.value(SEND_KEYSTROKES_KEY, "FALSE") == "TRUE");
    ui->thePostProcess->setText(nvPairs.value(POST_COMMAND_KEY, ""));

    bool numParseSuccess = false;
    int numInstances = nvPairs.value(NUM_INSTANCES, "1").toInt(&numParseSuccess);

    if ( numParseSuccess && (numInstances >= 1) && (numInstances < 1000) )
    {
        ui->theNumInstances->setValue(numInstances);
    }

    numParseSuccess = false;
    int timeoutVal = nvPairs.value(TIMEOUT_KEY, "5").toInt(&numParseSuccess);
    if ( numParseSuccess && (timeoutVal >= 1) && (timeoutVal <= 6000) )
    {
        ui->theTimeoutSecs->setValue(timeoutVal);
    }


}


void BlastProcessing::saveButtonPressed()
{
    QString name = QFileDialog::getSaveFileName(this,
                                                "Blast Processing Config File",
                                                QDir::currentPath(),
                                                "Blast Processing Config (*.bpcfg)");

    if (!name.isEmpty())
    {
        if (!name.endsWith(".bpcfg") && !QFile::exists(name))
        {
            name += ".bpcfg";
        }

        saveGuiConfigFile(name);
    }

}

void BlastProcessing::loadButtonPressed()
{
    QString name = QFileDialog::getOpenFileName(this,
                                                "Blast Processing Config File",
                                                QDir::currentPath(),
                                                "Blast Processing Config (*.bpcfg);;All Files(*)");

    if (!name.isEmpty())
    {
        loadGuiConfigFile(name);
    }
}

void BlastProcessing::invalidateConfig()
{
    qDebug() << "Configuration invalid";
    theStoredConfigValid = false;
}
