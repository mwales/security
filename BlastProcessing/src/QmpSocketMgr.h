#ifndef QMPSOCKETMGR_H
#define QMPSOCKETMGR_H

#include <QObject>
#include <QThread>
#include <QString>
#include <stdint.h>
#include <QJsonObject>
#include <QVector>
#include <QPair>

class SocketCommandInterface;

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

    void enableCommandQueueing(bool enable);

    // need to create signals thing we need to send to SocketCommandInterface

public slots:

    void handleQmpGreeting(QJsonObject msg);

    void handleQmpEvent(QJsonObject obj);

    void handleQmpReturn(QJsonObject obj);


signals:

    void connectSocket();

    void writeDataToSocket(QString msg);

    void closeSocket();

    void humanResponseReceived(QString text);

    void eventReceived(QString text);





protected:

    void sendQmpCapabilities();

    bool sendNoParamNoRespCommand(QString command);

    void dequeRemainingCommands();

    bool theQueuingFlag;

    enum class QmpState
    {
        NOT_CONNECTED,
        WAITING_FOR_GREETING,
        WAITING_FOR_CAPABILITY_RESPONSE,
        READY,
        WAITING_FOR_RESPONSE,
        WAITING_FOR_HUMAN_COMMAND_RESPONSE
    };

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

    QmpState theState;



    QThread* theSocketThread;

    SocketCommandInterface* theQmpSocket;


};

#endif // QMPSOCKETMGR_H
