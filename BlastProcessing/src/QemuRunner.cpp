#include "QemuRunner.h"
#include <QProcess>
#include <QtDebug>
#include <QProcessEnvironment>
#include <QThread>
#include <QCoreApplication>

#include "QemuConfiguration.h"
#include "QemuProcessManager.h"

QemuRunner::QemuRunner(int id, QemuConfiguration const & cfg):
    theState(RunnerState::NOT_RUNNING),
    theInstanceId(id),
    theCfg(cfg),
    theRunningProcess(nullptr),
    theProgressUpdateTimer(nullptr),
    theCurrentProcTime(-1),
    theRunFlag(false),
    theUseQemuFlag(false),
    theQemuProcess(nullptr),
    theSendQemuKeystrokesFlag(false)
{
    qDebug() << "QemuRunner ID" << id << "started";

    setTimeout(30);

    theProgressUpdateTimer = new QTimer(this);
}

void QemuRunner::stopTests()
{
    theRunFlag = false;
}

void QemuRunner::runnerThreadStart()
{
    qDebug() << "Qemu Runner Thread = " << QThread::currentThread() << ", ID=" << theInstanceId;

    if (theState != RunnerState::NOT_RUNNING)
    {
        qWarning() << "Runner thread not in the right state to start";
        return;
    }

    theProgressUpdateTimer = new QTimer(this);
    theProgressUpdateTimer->setInterval(1000);
    theProgressUpdateTimer->setSingleShot(false);
    connect(theProgressUpdateTimer,     &QTimer::timeout,
            this,                       &QemuRunner::tickUpdate);

    theRunFlag = true;

    theProgressUpdateTimer->start();

    startNextState();
}


void QemuRunner::setScripts(QString pre, QString peri, QString post)
{
    thePreScript  = pre;
    thePeriScript = peri;
    thePostScript = post;
}

void QemuRunner::setTimeout(int secs)
{
    qDebug() << "Instance " << theInstanceId << " timeout set to " << theTimeout << "secs";
    theTimeout = secs;
    theProgressPerTick = 100 / theTimeout;
}

void QemuRunner::runnerProcessError(QProcess::ProcessError err)
{
    // Even though a process crashed, you have to wait for the complete signal to get called
    qDebug() << "Pre-Process encountered an error" << theRunningProcess->errorString();
}

void QemuRunner::runnerProcessComplete(int exitCode)
{
    qDebug() << "QemuRunner Event Handler Thread = " << QThread::currentThread();
    qDebug() << "Process COMPLETE";

    theRunningProcess->deleteLater();

    startNextState();
}

void QemuRunner::tickUpdate()
{
    // qDebug() << "Tick " << theCurrentProcTime << " for instance " << theInstanceId
    //          << ", timeout at " << theTimeout << " ticks";

    if ( (theState == RunnerState::PRE_RUNNING) ||
         (theState == RunnerState::PERI_RUNNING) ||
         (theState == RunnerState::POST_RUNNING) )
    {
        theCurrentProcTime++;

        if (theState == RunnerState::PRE_RUNNING)
        {
            emit testProgress(0 + theProgressPerTick * theCurrentProcTime);
        }

        if (theState == RunnerState::PERI_RUNNING)
        {
            emit testProgress(100 + theProgressPerTick * theCurrentProcTime);
        }

        if (theState == RunnerState::POST_RUNNING)
        {
            emit testProgress(200 + theProgressPerTick * theCurrentProcTime);
        }

        if (theCurrentProcTime > theTimeout)
        {
            qDebug() << "We are going to have to forcefully kill the process";
            theRunningProcess->terminate();
        }
    }
}

void QemuRunner::startNextState()
{
    switch(theState)
    {
    case RunnerState::NOT_RUNNING:
        theState = RunnerState::STARTING_QEMU;

        if (theUseQemuFlag)
        {
            startQemu();
            return;
        }

        // Else, if not using QEMU, fall through intentionally...

    case RunnerState::STARTING_QEMU:
        // Intentional fall-through

    case RunnerState::SAVE_RESULTS:
        if (theRunFlag)
        {
            seeding();

            qDebug() << __PRETTY_FUNCTION__ << " going to start PRE script";
            theState = RunnerState::PRE_RUNNING;
            startScript(thePreScript);

            return;
        }
        else
        {
            // Stop QEMU
            stopQemu();
            return;
        }

    case RunnerState::PRE_RUNNING:
        qDebug() << __PRETTY_FUNCTION__ << " going to start PERI script";
        theState = RunnerState::PERI_RUNNING;
        startScript(thePeriScript);

        return;

    case RunnerState::PERI_RUNNING:
        qDebug() << __PRETTY_FUNCTION__ << " going to start POST script";
        theState = RunnerState::POST_RUNNING;

        // Need to load the snapshot and send keystrokes


        startScript(thePostScript);

        return;

    case RunnerState::POST_RUNNING:
        // save results
        emit testProgress(300);
        theState = RunnerState::SAVE_RESULTS;
        saveResults();
        return;
    }
}

void QemuRunner::startScript(QString scriptCommand)
{
    resetTimers();

    theRunningProcess = new QProcess();
    connect(theRunningProcess,            SIGNAL(error(QProcess::ProcessError)),
            this,                         SLOT(runnerProcessError(QProcess::ProcessError)));
    connect(theRunningProcess,            SIGNAL(finished(int)),
            this,                         SLOT(runnerProcessComplete(int)));

    std::map<std::string, std::string> envVars = theCfg.getProcessEnvironment();
    QProcessEnvironment qenv = QProcessEnvironment::systemEnvironment();
    int i = 0;
    for(auto singleVar = envVars.begin(); singleVar != envVars.end();  singleVar++)
    {
        qDebug() << "Setting environment variable #" << i++ << " to " << singleVar->first.c_str() << "="
                 << singleVar->second.c_str();

        qenv.insert(singleVar->first.c_str(), singleVar->second.c_str());
    }

    theRunningProcess->processEnvironment().swap(qenv);

    QStringList args;
    args.append("1");
    args.append("2");

    theRunningProcess->start(scriptCommand, args);
}

void QemuRunner::resetTimers()
{
    theCurrentProcTime = -1;
}

void QemuRunner::seeding()
{
    theTestId = qrand();
    qDebug() << "Seeding for " << theInstanceId << " = " << theTestId;

}

void QemuRunner::saveResults()
{
    qDebug() << "Save results";

    emit testComplete("What success");

    if (theRunFlag == false)
    {
        qDebug() << "Runner instance " << theInstanceId << " stopping";
        theProgressUpdateTimer->stop();
        emit runnerStopped(this);

    }
    else
    {
        startNextState();
    }
}

void QemuRunner::startQemu()
{
    qDebug() << __PRETTY_FUNCTION__;
    theQemuProcess = new QemuProcessManager(this);

    connect(theQemuProcess,       &QemuProcessManager::qemuQmpReady,
            this,                 &QemuRunner::qemuStarted);

    theQemuProcess->startEmulator(theCfg, theInstanceId);
}

void QemuRunner::qemuStarted()
{
    qDebug() << __PRETTY_FUNCTION__;
    startNextState();
}

void QemuRunner::stopQemu()
{
    if (theUseQemuFlag)
    {
        qDebug() << "Stopping QEMU";
        theQemuProcess->stopEmulator();
        qDebug() << "Returned after stopping QEMU emulator";
    }

    qDebug() << "Runner instance " << theInstanceId << " stopping";
    theProgressUpdateTimer->stop();
    emit runnerStopped(this);
}

void QemuRunner::useQemuEmulator(bool enable,
                                 QString snapshotName,
                                 bool sendKeystrokes,
                                 QString keystrokes)
{
    theUseQemuFlag = enable;
    if (theUseQemuFlag)
    {
        theQemuSnapshotName = snapshotName;
        theSendQemuKeystrokesFlag = sendKeystrokes;
        theQemuKeystrokes = keystrokes;
    }
    else
    {
        theQemuSnapshotName = "snapshotName""";
        theSendQemuKeystrokesFlag = false;
        theQemuKeystrokes = "";
    }
}
