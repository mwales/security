#ifndef QEMUPROCESSMANAGER_H
#define QEMUPROCESSMANAGER_H

#include <QObject>
#include <QString>
#include <stdint.h>
#include <vector>
#include <QProcess>
#include <QObject>

#include "QmpSocketMgr.h"
#include "QemuConfiguration.h"

class QemuProcessManager : public QObject
{
    Q_OBJECT

public:
    QemuProcessManager(QObject *parent = Q_NULLPTR);

    ~QemuProcessManager();

signals:

    void eventReceived(QString text);

    void hummanCommandResponse(QString text);

    void errorReport(QString text);

    void qemuQmpReady();

public slots:

    // Emulation control functions
    void startEmulator(QemuConfiguration & cfg, int instanceId = 0);

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

    void screenShot(QString filename);

    void sendHumanCommandViaQmp(QString hciCmd);

protected slots:

    void qemuStandardOutputReady();

    void qemuStandardErrorReady();

    void qemuError(QProcess::ProcessError err);

    void qemuFinished(int exitCode, QProcess::ExitStatus status);


protected:

    void reportError(QString text);

    QProcess* theProcess;

    QmpSocketMgr* theQmpController;

};

#endif // QEMUPROCESSMANAGER_H
