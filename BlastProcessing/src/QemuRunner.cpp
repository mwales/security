#include "QemuRunner.h"
#include <QProcess>
#include <QtDebug>
#include <QProcessEnvironment>
#include <QThread>
#include <QCoreApplication>

#include "QemuConfiguration.h"

QemuRunner::QemuRunner(int id, QemuConfiguration const & cfg):
    theInstanceId(id),
    theCfg(cfg)
{
    qDebug() << "QemuRunner ID" << id << "started";
}

void QemuRunner::stopTests()
{
    theRunFlag = false;
}

void QemuRunner::runQemu()
{
    qDebug() << "Qemu Runner Thread = " << QThread::currentThread() << ", ID=" << theInstanceId;

    theRunFlag = true;
    while(theRunFlag)
    {
        thePreProcess = new QProcess();
        connect(thePreProcess,                SIGNAL(error(QProcess::ProcessError)),
                this,                         SLOT(preProcessError(QProcess::ProcessError)));
        connect(thePreProcess,                SIGNAL(finished(int)),
                this,                         SLOT(preProcessComplete(int)));

        std::map<std::string, std::string> envVars = theCfg.getProcessEnvironment();
        QProcessEnvironment qenv = QProcessEnvironment::systemEnvironment();
        int i = 0;
        for(auto singleVar = envVars.begin(); singleVar != envVars.end();  singleVar++)
        {
            qDebug() << "Setting environment variable #" << i++ << " to " << singleVar->first.c_str() << "="
                     << singleVar->second.c_str();

            qenv.insert(singleVar->first.c_str(), singleVar->second.c_str());
        }

        thePreProcess->processEnvironment().swap(qenv);

        QStringList args;
        args.append("1");
        args.append("2");

        thePreInProgressFlag = true;

        thePreProcess->start(thePreScript, args);

        while(thePreInProgressFlag)
        {
            //qDebug() << "Runner waiting...";
            QCoreApplication::processEvents(QEventLoop::AllEvents, 1000);
        }

        qDebug() << "All done with that instance!";

        delete thePreProcess;



        QThread::sleep(3);
    }

    qDebug() << "Instance" << theInstanceId << "stopping...";
    emit runnerStopped(this);
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

void QemuRunner::preProcessError(QProcess::ProcessError err)
{
    qDebug() << "Pre-Process encountered an error" << thePreProcess->errorString();
}

void QemuRunner::preProcessComplete(int exitCode)
{
    qDebug() << "QemuRunner Event Handler Thread = " << QThread::currentThread();
    qDebug() << "PRE COMPLETE";
    thePreInProgressFlag = false;
}

void QemuRunner::periProcessError(QProcess::ProcessError err)
{

}

void QemuRunner::periProcessComplete(int exitCode, QProcess::ExitStatus exitStatus)
{

}

void QemuRunner::postProcessError(QProcess::ProcessError err)
{

}

void QemuRunner::postProcessComplete(int exitCode, QProcess::ExitStatus exitStatus)
{

}
