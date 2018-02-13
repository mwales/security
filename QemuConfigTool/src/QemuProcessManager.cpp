#include "QemuProcessManager.h"
#include <QtDebug>

// To support snapshots
//  Does query-qmp-schema tell us if qemu has QMP snapshot commands?
//    query-events may also be interesting...
//    query-commands



#ifdef QEMU_MGR_DEBUG
   #define QemuDebug     std::cout << "QEMU_DBG> [" << theInstanceId << "] "
   #define QemuDebugWarn std::cout << "QEMU_DBG> [" << theInstanceId << "] ** WARN ** "
#else
   #define QemuDebug     if(0) std::cout
   #define QemuDebugWarn if(0) std::cout
#endif

QemuProcessManager::QemuProcessManager(int instanceId, QObject *parent):
    QObject(parent),
    theProcess(nullptr),
    theQmpController(nullptr),
    theInstanceId(instanceId)
{
    // Intentionally empty
}

QemuProcessManager::QemuProcessManager(QObject *parent):
    QObject(parent),
    theProcess(nullptr),
    theQmpController(nullptr),
    theInstanceId(0)
{
    // Intentionally empty
}

QemuProcessManager::~QemuProcessManager()
{
    QemuDebug << __PRETTY_FUNCTION__ << std::endl;

    if (theQmpController && theProcess)
    {
        stopEmulator();

        if (theProcess->waitForFinished(3000))
        {
            QemuDebug << "QEMU exitted gracefully" << std::endl;
        }
        else
        {
            QemuDebug << "Told QEMU to quit, but it won't listen!!!" << std::endl;
        }
    }
    // theProcess cleaned up by QObject
}

bool QemuProcessManager::isRunning()
{
    if ( (theProcess->state() == QProcess::Running) ||
         (theProcess->state() == QProcess::Starting) )
    {
        return true;
    }
    else
    {
        return false;
    }
}

// Emulation control functions
void QemuProcessManager::startEmulator(QemuConfiguration & cfg)
{
    std::vector<std::string> args;
    std::string cmd;
    if (!cfg.getCommandLine(cmd, args, theInstanceId))
    {
        reportError("Error building emulator command, can't start!");
        return;
    }

    QString systemCommand = cmd.c_str();
    QStringList commandArgs;
    for(auto singleArg = args.begin(); singleArg != args.end(); singleArg++)
    {
            commandArgs.push_back(singleArg->c_str());
    }

    uint16_t qmpPortNum = cfg.getStartingPortNumber();
    qmpPortNum += theInstanceId * cfg.getNumberOfPortsPerInstance();

    if (theProcess != nullptr)
    {
        reportError("Emulator already running!");
        return;
    }

    QString commandLine = QString("%1 %2").arg(systemCommand).arg(commandArgs.join(" "));
    QemuDebug << "QEMU Command Line: " << commandLine.toStdString() << std::endl;

    theProcess = new QProcess(this);
    theProcess->setProgram(systemCommand);
    theProcess->setArguments(commandArgs);

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
        QemuDebug << "Process started successfully" << std::endl;
    }
    else
    {

        QemuDebugWarn << "Process failed to start" << std::endl;
    }

    theQmpController = new QmpSocketMgr("127.0.0.1", qmpPortNum, this);

    // Signals from the QMP object we are just passing up to the QemuProcessManager
    connect(theQmpController,      &QmpSocketMgr::eventReceived,
            this,                  &QemuProcessManager::eventReceived);
    connect(theQmpController,      &QmpSocketMgr::humanResponseReceived,
            this,                  &QemuProcessManager::hummanCommandResponse);
    connect(theQmpController,      &QmpSocketMgr::qmpInterfaceReady,
            this,                  &QemuProcessManager::qemuQmpReady);

}

void QemuProcessManager::stopEmulator()
{
    if (theQmpController == nullptr)
    {
        return;
    }

    if(!theQmpController->sendQuit())
    {
        QemuDebugWarn << "Error from QMP when sending the quit command" << std::endl;
    }
    else
    {
        QemuDebug << "Quit command sent successfully" << std::endl;
    }
}

void QemuProcessManager::pauseEmulator()
{
    if (!theQmpController->sendStop())
    {
        QemuDebugWarn << "Error from QMP when sending the stop command" << std::endl;
    }
    else
    {
        QemuDebug << "Stop command sent successfully" << std::endl;
    }
}

void QemuProcessManager::continueEmulator()
{
    if (!theQmpController->sendContinue())
    {
        QemuDebugWarn << "Error from QMP when sending the continue command" << std::endl;
    }
    else
    {
        QemuDebug << "Continue command sent successfully" << std::endl;
    }
}

void QemuProcessManager::resetEmulator()
{
    if (!theQmpController->sendReset())
    {
        QemuDebugWarn << "Error from QMP when sending the reset command" << std::endl;
    }
    else
    {
        QemuDebug << "Reset command sent successfully" << std::endl;
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

    QemuDebug << "saveEmulatorState completed successfully (commands probably queued)" << std::endl;
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
        QemuDebugWarn << "Error from QMP when sending the power off command" << std::endl;
    }
    else
    {
        QemuDebug << "Power off command sent successfully" << std::endl;
    }
}

void QemuProcessManager::screenShot(QString filename)
{
    if (!theQmpController->screendump(filename))
    {
        QemuDebugWarn << "Error from QMP when sending the screenshot command" << std::endl;
    }
    else
    {
        QemuDebug << "Screenshot command sent successfully" << std::endl;
    }
}

void QemuProcessManager::sendHumanCommandViaQmp(QString hciCmd)
{
    if (theQmpController == nullptr)
    {
        QemuDebugWarn << "There is no QEMU running to query for snapshot information" << std::endl;
        return;
    }

    if (!theQmpController->executeHumanMonitorCommand(hciCmd))
    {
        QemuDebugWarn << "Error from QMP when sending the humman command command" << std::endl;
    }
    else
    {
        QemuDebug << "Human command command sent successfully" << std::endl;
    }
}

void QemuProcessManager::qemuStandardOutputReady()
{
    QemuDebug << "QEMU-stdout:  " << theProcess->readAllStandardOutput().toStdString() << std::endl;
}

void QemuProcessManager::qemuStandardErrorReady()
{
    QemuDebug << "QEMU-stderr:  " << theProcess->readAllStandardError().toStdString() << std::endl;
}

void QemuProcessManager::qemuError(QProcess::ProcessError err)
{
    switch(err)
    {
    case QProcess::FailedToStart:
        QemuDebugWarn << "QEMU Failed to Start" << std::endl;
        break;

    case QProcess::Crashed:
        QemuDebugWarn << "QEMU Crashed!" << std::endl;
        break;

    case QProcess::Timedout:
        QemuDebugWarn << "QEMU Timed Out, whatever that means" << std::endl;
        break;

    case QProcess::WriteError:
        QemuDebugWarn << "QEMU Write Error" << std::endl;
        break;

    case QProcess::ReadError:
        QemuDebugWarn << "QEMU Read Error" << std::endl;
        break;

    case QProcess::UnknownError:
        QemuDebugWarn << "QEMU Unknown Error" << std::endl;
        break;

    default:
        QemuDebugWarn << "QEMU undocumented error!" << std::endl;

    }

    delete theProcess;
    theProcess = nullptr;
}

void QemuProcessManager::qemuFinished(int exitCode, QProcess::ExitStatus status)
{
    switch(status)
    {
    case QProcess::NormalExit:
        QemuDebug << "QEMU finished normally, exit code =" << exitCode << std::endl;
        break;

    case QProcess::CrashExit:
        QemuDebugWarn << "QEMU finished with a splosion, exit code =" << exitCode << std::endl;
        break;

    default:
        QemuDebugWarn << "QEMU has an invalid exit status, exit code =" << exitCode << std::endl;
    }

    emit qemuStopped();

    theProcess->deleteLater();
    theProcess = nullptr;
}

void QemuProcessManager::reportError(QString text)
{
    /** TODO: Actually use this reportError function in more than occasional places, and make it
     *        do something useful for the user (like a message box) */

    QemuDebugWarn << "QemuProcessManager:" << text.toStdString() << std::endl;
    emit errorReport(text);
}
