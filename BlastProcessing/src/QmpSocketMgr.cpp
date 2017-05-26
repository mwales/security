#include "QmpSocketMgr.h"
#include "SocketCommandInterface.h"
QmpSocketMgr::QmpSocketMgr(QString host, uint16_t portNumber, QObject* parent)
{
    theQmpSocket = new SocketCommandInterface(host, portNumber);

    theSocketThread = new QThread();

    theQmpSocket->moveToThread(theSocketThread);
    theSocketThread->start();

    connect(this,         &QmpSocketMgr::connectSocket,
            theQmpSocket, &SocketCommandInterface::startConnection);
    connect(this,         &QmpSocketMgr::writeDataToSocket,
            theQmpSocket, &SocketCommandInterface::writeData);
    connect(this,         &QmpSocketMgr::closeSocket,
            theQmpSocket, &SocketCommandInterface::destroyConnection,
            Qt::BlockingQueuedConnection);

    qDebug() << "Got here!";

    emit connectSocket();
}

QmpSocketMgr::~QmpSocketMgr()
{
    emit closeSocket();

    theSocketThread->exit();

    delete theSocketThread;

    delete theQmpSocket;


}

QString QmpSocketMgr::executeHumanMonitorCommand(QString cmd)
{

}

bool QmpSocketMgr::enableVnc()
{

}

bool QmpSocketMgr::disableVnc()
{

}

QString QmpSocketMgr::queryVnc()
{

}

bool QmpSocketMgr::screendump(QString filename)
{

}

bool QmpSocketMgr::sendStop()
{

}

bool QmpSocketMgr::sendPowerOff()
{

}

bool QmpSocketMgr::sendContinue()
{

}

bool QmpSocketMgr::sendReset()
{

}

bool QmpSocketMgr::saveSnapshot(QString snapshotName)
{

}

QString QmpSocketMgr::querySnapshots()
{

}

bool QmpSocketMgr::loadSnapshot(QString snapshotName)
{

}
