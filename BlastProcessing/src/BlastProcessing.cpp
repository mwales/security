#include "BlastProcessing.h"
#include "ui_BlastProcessing.h"

#include <QThreadPool>
#include <QtDebug>
#include <QProgressDialog>
#include <QCloseEvent>

#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QProgressBar>
#include <QLineEdit>

#include "QemuConfiguration.h"
#include "QemuRunner.h"

const int NUM_RUNNER_UI_CONTROLS = 25;

BlastProcessing::BlastProcessing(QemuConfiguration const & cfg, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::BlastProcessing),
    theCfg(cfg),
    theNumInstancesToRun(0)
{
    ui->setupUi(this);

    connect(ui->theStartButton,       &QPushButton::clicked,
            this,                     &BlastProcessing::startButtonPressed);
    connect(ui->theStopButton,        &QPushButton::clicked,
            this,                     &BlastProcessing::stopButtonPressed);

    connect(&theSignalMapper,         SIGNAL(mapped(QObject*)),
            this,                     SLOT(runnerStopped(QemuRunner*)));

    connect(ui->theNumInstances,      SIGNAL(valueChanged(int)),
            this,                     SLOT(setNumInstancesUpdated(int)));

    createProgressControls();

    theStatusLayout = new QVBoxLayout();
    ui->theRunnerStatusBox->setLayout(theStatusLayout);
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
