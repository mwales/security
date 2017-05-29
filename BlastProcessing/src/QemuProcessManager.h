#ifndef QEMUPROCESSMANAGER_H
#define QEMUPROCESSMANAGER_H

#include <QObject>
#include <QString>
#include <stdint.h>
#include <vector>
#include <QProcess>
#include <QObject>

#include "QmpSocketMgr.h"

class QemuProcessManager : public QObject
{
    Q_OBJECT

public:
    QemuProcessManager(QObject *parent = Q_NULLPTR);

    ~QemuProcessManager();




    // Emulation setup options
    bool addDriveFile(QString filename);

    bool setProcessorType(QString processorName);

    bool setNetworkAdapterType(QString networkAdapterName);

    //bool setQmpSocketNumber(uint16_t portNumber);

    /**
     * Allows someone to configure the human interface on, the port number will be calculated as
     * +1 of the QMP port number
     */
    void enableHumanInterfaceSocket(bool enable);

    bool setOtherOptions(QString otherOptions);

    void setMemorySize(uint16_t numMegabytes);

    int getNumberOfPortsPerInstance();

    void setStartingPortNumber(uint16_t portNumber);

signals:

    void connectToQmp();

public slots:

    // Emulation control functions
    void startEmulator();

    /**
     * Stops the QEMU process via the quit command
     */
    void stopEmulator();

    /**
     * Pauses emulation by sending QEMU the stop command, can be resumed again
     */
    void pauseEmulator();

    /**
     * Tells QEMU to resume emulation after a pause was executed
     */
    void continueEmulator();

    /**
     * Tells QEMU to reset the emulator
     */
    void resetEmulator();

    void saveEmulatorState(QString filename);

    void loadEmulatorState(QString filename);

    /**
     * @brief powerEmulatorOff
     */
    void powerEmulatorOff();

protected slots:

    void qemuStandardOutputReady();

    void qemuStandardErrorReady();

    void qemuError(QProcess::ProcessError err);

    void qemuFinished(int exitCode, QProcess::ExitStatus status);


protected:

    bool buildCommand();

    bool buildDriveArgs();

    bool buildNetworkArgs();

    bool buildQmpArgs();

    bool buildMonitorSocketArgs();

    bool buildOtherArgs();

    bool buildMemoryArgs();

    std::vector<QString> theDriveFiles;

    QString theCpuType;

    QStringList theSystemCommandArgs;
    QString theSystemCommand;

    QProcess* theProcess;

    uint16_t theMemoryMb;

    uint16_t theStartingPortNumber;

    bool theHumanInterfaceEnabled;

    QmpSocketMgr* theQmpController;

    // todo: other processors besides i386 (query machines switch of qemu)

    // todo: network adapters

    // todo: ramsize

    // boot options

    // hard drive files

    // cdrom drive file

    // display (vga, no display, sdl)

    // port numbers to use for QMP sockets

    // human management interface (can i do this and QMP at the same time?)

    // other / generic options

};

#endif // QEMUPROCESSMANAGER_H
