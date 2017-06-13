#include "QemuProcessManager.h"
#include <QtDebug>

// To support snapshots
//  Does query-qmp-schema tell us if qemu has QMP snapshot commands?
//    query-events may also be interesting...
//    query-commands

QemuProcessManager::QemuProcessManager(QObject *parent):
    QObject(parent),
    theProcess(nullptr),
    theStartingPortNumber(20000),
    theQmpController(nullptr)
{

}

QemuProcessManager::~QemuProcessManager()
{
    qDebug() << __PRETTY_FUNCTION__;

    if (theQmpController && theProcess)
    {
        stopEmulator();

        if (theProcess->waitForFinished(3000))
        {
            qDebug() << "QEMU exitted gracefully";
        }
        else
        {
            qDebug() << "Told QEMU to quit, but it won't listen!!!";
        }
    }
    // theProcess cleaned up by QObject
}



// Emulation control functions
void QemuProcessManager::startEmulator(QemuConfiguration const & cfg)
{
    std::vector<std::string> args;
    std::string cmd;
    if (!cfg.getCommandLine(cmd, args))
    {
        reportError("Error building emulator command, can't start!");
        return;
    }

    theSystemCommand = cmd.c_str();
    for(auto singleArg = args.begin(); singleArg != args.end(); singleArg++)
    {
            theSystemCommandArgs.push_back(singleArg->c_str());
    }
    theStartingPortNumber = cfg.getStartingPortNumber();

    if (theProcess != nullptr)
    {
        reportError("Emulator already running!");
        return;
    }

    theProcess = new QProcess(this);
    theProcess->setProgram(theSystemCommand);
    theProcess->setArguments(theSystemCommandArgs);

    connect(theProcess, &QProcess::readyReadStandardOutput,
            this,       &QemuProcessManager::qemuStandardOutputReady);
    connect(theProcess, &QProcess::readyReadStandardError,
            this,       &QemuProcessManager::qemuStandardErrorReady);
    connect(theProcess, SIGNAL(error(QProcess::ProcessError)),
            this,       SLOT(qemuError(QProcess::ProcessError)));
    connect(theProcess, SIGNAL(finished(int,QProcess::ExitStatus)),
            this,       SLOT(qemuFinished(int,QProcess::ExitStatus)));

    theProcess->start();

    if (theProcess->waitForStarted())
    {
        qDebug() << "Process started successfully";
    }
    else
    {
        qWarning() << "Process failed to start";
    }

    theQmpController = new QmpSocketMgr("127.0.0.1", theStartingPortNumber, this);

    connect(theQmpController,      &QmpSocketMgr::eventReceived,
            this,                  &QemuProcessManager::eventReceived);
    connect(theQmpController,      &QmpSocketMgr::humanResponseReceived,
            this,                  &QemuProcessManager::hummanCommandResponse);

}

void QemuProcessManager::stopEmulator()
{
    if (theQmpController == nullptr)
    {
        return;
    }

    if(!theQmpController->sendQuit())
    {
        qDebug() << "Error from QMP when sending the quit command";
    }
    else
    {
        qDebug() << "Quit command sent successfully";
    }
}

void QemuProcessManager::pauseEmulator()
{
    if (!theQmpController->sendStop())
    {
        qDebug() << "Error from QMP when sending the stop command";
    }
    else
    {
        qDebug() << "Stop command sent successfully";
    }
}

void QemuProcessManager::continueEmulator()
{
    if (!theQmpController->sendContinue())
    {
        qDebug() << "Error from QMP when sending the continue command";
    }
    else
    {
        qDebug() << "Continue command sent successfully";
    }
}

void QemuProcessManager::resetEmulator()
{
    if (!theQmpController->sendReset())
    {
        qDebug() << "Error from QMP when sending the reset command";
    }
    else
    {
        qDebug() << "Reset command sent successfully";
    }
}


void QemuProcessManager::saveEmulatorState(QString filename)
{
    if (!theQmpController->sendStop())
    {
        reportError("Failed when sending the stop command (before saving VM)");
        return;
    }

    QString saveVmCmd = QString("savevm %1").arg(filename);
    if (!theQmpController->executeHumanMonitorCommand(saveVmCmd))
    {
        reportError("Failed to send the savevm command");
        return;
    }

    if (!theQmpController->sendContinue())
    {
        reportError("Failed to continue emulation after saving VM state");
        return;
    }

    qDebug() << "saveEmulatorState completed successfully (commands probably queued)";
}

void QemuProcessManager::loadEmulatorState(QString filename)
{
    QString loadCmd = QString("loadvm %1").arg(filename);

    if (!theQmpController->executeHumanMonitorCommand(loadCmd))
    {
        reportError("Failed to send the loadvm command");
    }
}

void QemuProcessManager::powerEmulatorOff()
{
    if (!theQmpController->sendPowerOff())
    {
        qDebug() << "Error from QMP when sending the power off command";
    }
    else
    {
        qDebug() << "Power off command sent successfully";
    }
}

void QemuProcessManager::screenShot(QString filename)
{
    if (!theQmpController->screendump(filename))
    {
        qDebug() << "Error from QMP when sending the screenshot command";
    }
    else
    {
        qDebug() << "Screenshot command sent successfully";
    }
}

void QemuProcessManager::sendHumanCommandViaQmp(QString hciCmd)
{
    if (!theQmpController->executeHumanMonitorCommand(hciCmd))
    {
        qDebug() << "Error from QMP when sending the humman command command";
    }
    else
    {
        qDebug() << "Human command command sent successfully";
    }
}

void QemuProcessManager::qemuStandardOutputReady()
{
    qDebug() << "QEMU-stdout:  " << theProcess->readAllStandardOutput();
}

void QemuProcessManager::qemuStandardErrorReady()
{
    qDebug() << "QEMU-stderr:  " << theProcess->readAllStandardError();
}

void QemuProcessManager::qemuError(QProcess::ProcessError err)
{
    switch(err)
    {
    case QProcess::FailedToStart:
        qWarning() << "QEMU Failed to Start";
        break;

    case QProcess::Crashed:
        qWarning() << "QEMU Crashed!";
        break;

    case QProcess::Timedout:
        qWarning() << "QEMU Timed Out, whatever that means";
        break;

    case QProcess::WriteError:
        qWarning() << "QEMU Write Error";
        break;

    case QProcess::ReadError:
        qWarning() << "QEMU Read Error";
        break;

    case QProcess::UnknownError:
        qWarning() << "QEMU Unknown Error";
        break;

    default:
        qWarning() << "QEMU undocumented error!";

    }
}

void QemuProcessManager::qemuFinished(int exitCode, QProcess::ExitStatus status)
{
    switch(status)
    {
    case QProcess::NormalExit:
        qDebug() << "QEMU finished normally, exit code =" << exitCode;
        break;

    case QProcess::CrashExit:
        qDebug() << "QEMU finished with a splosion, exit code =" << exitCode;
        break;

    default:
        qDebug() << "QEMU has an invalid exit status, exit code =" << exitCode;
    }

    theProcess->deleteLater();
    theProcess = nullptr;
}

void QemuProcessManager::reportError(QString text)
{
    /** TODO: Actually use this reportError function in more than occasional places, and make it
     *        do something useful for the user (like a message box) */

    qWarning() << "QemuProcessManager:" << text;
    emit errorReport(text);
}
