#include "QemuRunner.h"
#include <QProcess>
#include <QtDebug>
#include <QProcessEnvironment>
#include <QThread>
#include <QCoreApplication>

#include "QemuConfiguration.h"



QemuRunner::QemuRunner(int id, QemuConfiguration const & cfg):
    theState(RunnerState::NOT_RUNNING),
    theInstanceId(id),
    theCfg(cfg),
    theRunningProcess(nullptr),
    theProgressUpdateTimer(nullptr),
    theTimeout(30),
    theCurrentProcTime(-1),
    theRunFlag(false)
{
    qDebug() << "QemuRunner ID" << id << "started";

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
    theTimeout = secs;
}

void QemuRunner::runnerProcessError(QProcess::ProcessError err)
{
    qDebug() << "Pre-Process encountered an error" << theRunningProcess->errorString();

    startNextState();
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


    if ( (theState == RunnerState::PRE_RUNNING) ||
         (theState == RunnerState::PERI_RUNNING) ||
         (theState == RunnerState::POST_RUNNING) )
    {
        theCurrentProcTime++;

        if (theState == RunnerState::PRE_RUNNING)
        {
            emit testProgress(1,theCurrentProcTime);
        }

        if (theState == RunnerState::PRE_RUNNING)
        {
            emit testProgress(2,theCurrentProcTime);
        }

        if (theState == RunnerState::PRE_RUNNING)
        {
            emit testProgress(3,theCurrentProcTime);
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
    case RunnerState::SAVE_RESULTS:
        seeding();

        qDebug() << __PRETTY_FUNCTION__ << " going to start PRE script";
        theState = RunnerState::PRE_RUNNING;
        startScript(thePreScript);

        return;

    case RunnerState::PRE_RUNNING:
        qDebug() << __PRETTY_FUNCTION__ << " going to start PERI script";
        theState = RunnerState::PERI_RUNNING;
        startScript(thePeriScript);

        return;

    case RunnerState::PERI_RUNNING:
        qDebug() << __PRETTY_FUNCTION__ << " going to start POST script";
        theState = RunnerState::POST_RUNNING;
        startScript(thePostScript);

        return;

    case RunnerState::POST_RUNNING:
        // save results
        theState = RunnerState::SAVE_RESULTS;
        saveResults();
        return;

    }


}

void QemuRunner::startScript(QString scriptCommand)
{
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
    theTimeout = -1;
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
        runnerStopped(this);
    }
    else
    {
        startNextState();
    }
}
