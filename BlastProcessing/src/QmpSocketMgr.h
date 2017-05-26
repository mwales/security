#ifndef QMPSOCKETMGR_H
#define QMPSOCKETMGR_H

#include <QObject>
#include <QThread>
#include <QString>
#include <stdint.h>

class SocketCommandInterface;

class QmpSocketMgr : public QObject
{

    Q_OBJECT

public:

    QmpSocketMgr(QString host, uint16_t portNumber, QObject* parent = nullptr);
    ~QmpSocketMgr();

    QString executeHumanMonitorCommand(QString cmd);

    bool enableVnc();
    bool disableVnc();
    QString queryVnc();

    bool screendump(QString filename);

    bool sendStop();
    bool sendPowerOff();
    bool sendContinue();
    bool sendReset();

    bool saveSnapshot(QString snapshotName);
    QString querySnapshots();
    bool loadSnapshot(QString snapshotName);

    // need to create signals thing we need to send to SocketCommandInterface
signals:

    void connectSocket();

    void writeDataToSocket(QString msg);

    void closeSocket();





protected:

    QThread* theSocketThread;

    SocketCommandInterface* theQmpSocket;


};

#endif // QMPSOCKETMGR_H
