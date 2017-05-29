#include "QemuProcessManager.h"
#include <QtDebug>


QemuProcessManager::QemuProcessManager(QObject *parent):
    QObject(parent),
    theProcess(nullptr),
    theMemoryMb(256),
    theStartingPortNumber(20000),
    theHumanInterfaceEnabled(true)
{

}

QemuProcessManager::~QemuProcessManager()
{
    qDebug() << __PRETTY_FUNCTION__;

    stopEmulator();

    if (theProcess->waitForFinished(3000))
    {
        qDebug() << "QEMU exitted gracefully";
    }
    else
    {
        qDebug() << "Told QEMU to quit, but it won't listen!!!";
    }
    // theProcess cleaned up by QObject
}



// Emulation control functions
void QemuProcessManager::startEmulator()
{
    if (!buildCommand())
    {
        qDebug() << "Error building emulator command, can't start!";
        return;
    }

    if (theProcess != nullptr)
    {
        qDebug() << "Emulator already running!";
        return;
    }

    theProcess = new QProcess(this);
    theProcess->setProgram(theSystemCommand);
    theProcess->setArguments(theSystemCommandArgs);

    connect(theProcess, &QProcess::readyReadStandardOutput,
            this, &QemuProcessManager::qemuStandardOutputReady);
    connect(theProcess, &QProcess::readyReadStandardError,
            this, &QemuProcessManager::qemuStandardErrorReady);
    connect(theProcess, SIGNAL(error(QProcess::ProcessError)),
            this, SLOT(qemuError(QProcess::ProcessError)));
    connect(theProcess, SIGNAL(finished(int,QProcess::ExitStatus)),
            this, SLOT(qemuFinished(int,QProcess::ExitStatus)));

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

}

void QemuProcessManager::stopEmulator()
{
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
    qDebug() << __PRETTY_FUNCTION__ << " not implemented yet (" << filename << ")";
}

void QemuProcessManager::loadEmulatorState(QString filename)
{
    qDebug() << __PRETTY_FUNCTION__ << " not implemented yet (" << filename << ")";
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

// Emulation setup options
bool QemuProcessManager::addDriveFile(QString filename)
{
    if (theDriveFiles.size() >= 4)
    {
        qWarning() << "Already have 4 drives, and addDriveFile called(" << filename << ")";
        return false;
    }

    theDriveFiles.push_back(filename);
    return true;
}

bool QemuProcessManager::setProcessorType(QString processorName)
{
    theCpuType = processorName;
    return true;
}

bool QemuProcessManager::setNetworkAdapterType(QString networkAdapterName)
{
    qDebug() << __PRETTY_FUNCTION__ << " not implemented yet (" << networkAdapterName << ")";
    return false;
}



void QemuProcessManager::enableHumanInterfaceSocket(bool enable)
{
    theHumanInterfaceEnabled = enable;
}

bool QemuProcessManager::setOtherOptions(QString otherOptions)
{
    qDebug() << __PRETTY_FUNCTION__ << " not implemented yet (" << otherOptions << ")";
    return false;
}

void QemuProcessManager::setMemorySize(uint16_t numMegabytes)
{
    theMemoryMb = numMegabytes;
}

int QemuProcessManager::getNumberOfPortsPerInstance()
{
    qDebug() << __PRETTY_FUNCTION__ << " not implemented yet";
    return -1;
}

void QemuProcessManager::setStartingPortNumber(uint16_t portNumber)
{
    theStartingPortNumber = portNumber;
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

bool QemuProcessManager::buildCommand()
{
    QString retVal;
    theSystemCommand = "qemu-system-";

    if (theCpuType.isEmpty())
    {
        qWarning() << "Must specify a CPU type before starting emulator";
        return false;
    }

    theSystemCommand += theCpuType;

    theSystemCommandArgs.clear();
    bool success;
    success = buildDriveArgs();
    success = success && buildNetworkArgs();
    success = success && buildQmpArgs();
    success = success && buildMonitorSocketArgs();
    success = success && buildOtherArgs();
    success = success && buildMemoryArgs();

    if (!success)
    {
        qWarning() << "Failed to build the command";
        return false;
    }

    qDebug() << "Command:" << theSystemCommand;
    qDebug() << "Args   :" << theSystemCommandArgs.join(" ");
    return success;
}

bool QemuProcessManager::buildDriveArgs()
{
    if (theDriveFiles.empty())
    {
        qWarning() << "No drive files specified!";
        return true;   // Maybe it booting off CDROM or some other memory?
    }

    foreach(QString singleDrive, theDriveFiles)
    {
        theSystemCommandArgs.append("-drive");

        QString filearg = "file=";
        filearg += singleDrive;
        theSystemCommandArgs.append(filearg);
    }

    return true;
}

bool QemuProcessManager::buildNetworkArgs()
{
    theSystemCommandArgs.append("-net");
    theSystemCommandArgs.append("nic,model=ne2k_pci,name=testNet");
    theSystemCommandArgs.append("-net");
    theSystemCommandArgs.append("user,id=testNet,hostfwd=tcp:127.0.0.1:2222-:23");
    return true;

}

bool QemuProcessManager::buildQmpArgs()
{
    theSystemCommandArgs.append("-qmp");
    QString devCfg = QString("tcp::%1,server,nowait").arg(theStartingPortNumber);
    theSystemCommandArgs.append(devCfg);
    return true;
}

bool QemuProcessManager::buildMonitorSocketArgs()
{
    if (theHumanInterfaceEnabled)
    {
        theSystemCommandArgs.append("-monitor");
        QString devCfg = QString("tcp::%1,server,nowait").arg(theStartingPortNumber+1);
        theSystemCommandArgs.append(devCfg);
    }

    return true;
}

bool QemuProcessManager::buildOtherArgs()
{


    theSystemCommandArgs.append("-display");
    theSystemCommandArgs.append("sdl");
    return true;
}

bool QemuProcessManager::buildMemoryArgs()
{
    theSystemCommandArgs.append("-m");
    theSystemCommandArgs.append(QString::number(theMemoryMb));
    return true;
}
