#include "BlastProcessing.h"
#include "ui_BlastProcessing.h"

#include <QThreadPool>
#include <QtDebug>
#include <QProgressDialog>
#include <QCloseEvent>

#include "QemuConfiguration.h"
#include "QemuRunner.h"

BlastProcessing::BlastProcessing(QemuConfiguration const & cfg, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::BlastProcessing),
    theCfg(cfg)
{
    ui->setupUi(this);

    connect(ui->theStartButton,       &QPushButton::clicked,
            this,                     &BlastProcessing::startButtonPressed);
    connect(ui->theStopButton,        &QPushButton::clicked,
            this,                     &BlastProcessing::stopButtonPressed);

    connect(&theSignalMapper,         SIGNAL(mapped(QObject*)),
            this,                     SLOT(runnerStopped(QemuRunner*)));

}

BlastProcessing::~BlastProcessing()
{
    stopThreadsAndWait();

    delete ui;
}

void BlastProcessing::startButtonPressed()
{
    QemuRunner* runner = new QemuRunner(2, theCfg);
    QThread* runnerThread = new QThread();
    runner->moveToThread(runnerThread);

    qDebug() << "RunnerThreaed = " << runnerThread;

    connect(runner,       &QemuRunner::runnerStopped,
            this,         &BlastProcessing::runnerStopped);
    connect(runnerThread, &QThread::started,
            runner,       &QemuRunner::runQemu);

    theSignalMapper.setMapping(runnerThread, runner);

    connect(runnerThread,     SIGNAL(finished()),
            &theSignalMapper, SLOT(map()));

    runner->setScripts(ui->thePreProcess->text(),
                       ui->thePeriProcess->text(),
                       ui->thePostProcess->text());
    runner->setTimeout(ui->theTimeoutSecs->value());

    qDebug() << "Blast Processing Thread = " << QThread::currentThread();
    runnerThread->start();

    theRunners.insert({runner, runnerThread});
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
        singleRunner.first->stopTests();
    }
}

void BlastProcessing::runnerStopped(QemuRunner* stoppedRunner)
{
    if (theRunners.find(stoppedRunner) != theRunners.end())
    {
        qDebug() << "Runner" << stoppedRunner->getInstanceId() << "stopped";
        QThread* runnerThread = theRunners[stoppedRunner];


        delete stoppedRunner;

        // I want to delete the thread here, but I always get a thread deleted while running
        // error...

        theRunners.erase(stoppedRunner);
    }
    else
    {
        qWarning() << "Runner" << stoppedRunner->getInstanceId()
                 << "stopped, but we don't have record of it starting";
    }
}

void BlastProcessing::stopThreadsAndWait()
{
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
