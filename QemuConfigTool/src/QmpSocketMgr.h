#ifndef QMPSOCKETMGR_H
#define QMPSOCKETMGR_H

#include <stdint.h>

#include <QObject>
#include <QThread>
#include <QString>
#include <QJsonObject>
#include <QVector>
#include <QPair>

class SocketCommandInterface;

/**
 * This class sends messages to QEMU via a QMP socket.  This class handles the JSON serialization
 * and deserialization for the user. It also handles queueing commands for QEMU if the interface
 * hasn't been established yet, or is waiting for a response from previous command.
 */
class QmpSocketMgr : public QObject
{

    Q_OBJECT

public:

    QmpSocketMgr(QString host, uint16_t portNumber, QObject* parent = nullptr);
    ~QmpSocketMgr();

    bool executeHumanMonitorCommand(QString cmd);

    bool enableVnc();
    bool disableVnc();
    QString queryVnc();

    bool screendump(QString filename);

    bool sendQuit();
    bool sendStop();
    bool sendPowerOff();
    bool sendContinue();
    bool sendReset();

    bool sendCommandQuery();

    bool saveSnapshot(QString snapshotName);
    QString querySnapshots();
    bool loadSnapshot(QString snapshotName);

signals:

    void humanResponseReceived(QString text);

    void eventReceived(QString text);

    void qmpInterfaceReady();

    /**
     * These three signals are consumed by SocketCommandInterface, callers should ignore
     */
    void connectSocket();
    void writeDataToSocket(QString msg);
    void closeSocket();

protected slots:

    // Slots are called data received by the SocketCommandInterface object

    void handleQmpGreeting(QJsonObject msg);

    void handleQmpEvent(QJsonObject obj);

    void handleQmpReturn(QJsonObject obj);

protected:
    /// This sends the QMP response to the greeting it gives us to bring the QMP interface operational
    void sendQmpCapabilities();

    /// Send a simple QMP command with no return data expected
    bool sendNoParamNoRespCommand(QString command);

    /// Called after getting a response that sends the state machine back to the READY state
    void dequeRemainingCommands();

    enum class QueuedCommandType
    {
        HUMAN_MONITOR_COMMAND,
        ENABLE_VNC,
        DISABLE_VNC,
        QUERY_VNC,
        SCREENDUMP,
        NO_RESPONSE_QMP,
        SAVE_SNAPSHOT,
        LOAD_SNAPSHOT
    };

    QVector< QPair< QueuedCommandType, QString> > theQueue;

    enum class QmpState
    {
        NOT_CONNECTED,
        WAITING_FOR_GREETING,
        WAITING_FOR_CAPABILITY_RESPONSE,
        READY,
        WAITING_FOR_RESPONSE,
        WAITING_FOR_HUMAN_COMMAND_RESPONSE
    };

    QmpState theState;

    /// The low-leve socket communication code runs in it's own thread
    QThread* theSocketThread;

    SocketCommandInterface* theQmpSocket;
};

#endif // QMPSOCKETMGR_H
