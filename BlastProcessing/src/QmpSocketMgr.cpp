#include "QmpSocketMgr.h"
#include "SocketCommandInterface.h"
#include <QJsonValue>
#include <QJsonArray>
#include <QJsonDocument>

const QString EXECUTE_KEY   = "execute";
const QString RETURN_KEY    = "return";
const QString ARGUMENTS_KEY = "arguments";

const QString EVENT_KEY  = "event";
const QString EVENT_TS_KEY = "timestamp";
const QString EVENT_TS_SECS = "seconds";
const QString EVENT_TS_USECS = "microseconds";


QmpSocketMgr::QmpSocketMgr(QString host, uint16_t portNumber, QObject* parent):
    QObject(parent),
    theState(QmpState::NOT_CONNECTED)
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

    connect(theQmpSocket, &SocketCommandInterface::greetingMessage,
            this,         &QmpSocketMgr::handleQmpGreeting);
    connect(theQmpSocket, &SocketCommandInterface::eventMessage,
            this,         &QmpSocketMgr::handleQmpEvent);
    connect(theQmpSocket, &SocketCommandInterface::returnMessage,
            this,         &QmpSocketMgr::handleQmpReturn);

    qDebug() << "Got here!";

    emit connectSocket();

    theState = QmpState::WAITING_FOR_GREETING;
}

QmpSocketMgr::~QmpSocketMgr()
{
    emit closeSocket();

    theSocketThread->exit();
    if (theSocketThread->wait(3000))
    {
        qDebug() << "The socket thread exitted gracefully";
    }
    else
    {
        qDebug() << "The socket thread didn't exit gracefully";
    }

    delete theSocketThread;

    delete theQmpSocket;


}

bool QmpSocketMgr::executeHumanMonitorCommand(QString cmd)
{
    qDebug() << __PRETTY_FUNCTION__ << "(" << cmd << ")";

    if (theState != QmpState::READY)
    {
        qDebug() << "QEMU QMP interface not ready to send human monitor command";
        return false;
    }

    QJsonObject jo;
    QJsonValue cmdName("human-monitor-command");

    jo.insert(EXECUTE_KEY, cmdName);

    QJsonObject argObj;
    argObj.insert("command-line", QJsonValue(cmd));

    jo.insert(ARGUMENTS_KEY, argObj);

    QJsonDocument jdoc;
    jdoc.setObject(jo);

    qDebug() << "About to send human monitor command";

    emit writeDataToSocket(jdoc.toJson(QJsonDocument::Compact));
    theState = QmpState::WAITING_FOR_HUMAN_COMMAND_RESPONSE;
    return true;
}

bool QmpSocketMgr::enableVnc()
{
    qDebug() << __PRETTY_FUNCTION__;
    return false;
}

bool QmpSocketMgr::disableVnc()
{
    return false;
}

QString QmpSocketMgr::queryVnc()
{
    return "";
}

bool QmpSocketMgr::screendump(QString filename)
{
    qDebug() << __PRETTY_FUNCTION__ << "(" << filename << ")";

    if (theState != QmpState::READY)
    {
        qDebug() << "QEMU QMP interface not ready to send screendump command";
        return false;
    }

    QJsonObject jo;
    QJsonValue cmdName("screendump");

    jo.insert(EXECUTE_KEY, cmdName);

    QJsonObject argObj;
    argObj.insert("filename", QJsonValue(filename));

    jo.insert(ARGUMENTS_KEY, argObj);

    QJsonDocument jdoc;
    jdoc.setObject(jo);

    qDebug() << "About to send screedump command";

    emit writeDataToSocket(jdoc.toJson(QJsonDocument::Compact));
    theState = QmpState::WAITING_FOR_RESPONSE;
    return true;
}

bool QmpSocketMgr::sendQuit()
{
    return sendNoParamNoRespCommand("quit");
}

bool QmpSocketMgr::sendStop()
{
    return sendNoParamNoRespCommand("stop");
}

bool QmpSocketMgr::sendPowerOff()
{
    return sendNoParamNoRespCommand("system_powerdown");
}

bool QmpSocketMgr::sendContinue()
{
    return sendNoParamNoRespCommand("cont");
}

bool QmpSocketMgr::sendReset()
{
    return sendNoParamNoRespCommand("system_reset");
}

bool QmpSocketMgr::sendCommandQuery()
{
    return sendNoParamNoRespCommand("query-commands");
}

bool QmpSocketMgr::saveSnapshot(QString snapshotName)
{
    qDebug() << __PRETTY_FUNCTION__ << "(" << snapshotName << ")";
    return false;
}

QString QmpSocketMgr::querySnapshots()
{
    return "";
}

bool QmpSocketMgr::loadSnapshot(QString snapshotName)
{
    qDebug() << __PRETTY_FUNCTION__ << "(" << snapshotName << ")";
    return false;
}

void QmpSocketMgr::handleQmpGreeting(QJsonObject msg)
{
    // We will retrieve the version of Qemu from the greeting

    const QString QMP_GREETING_KEY = "QMP";
    const QString QMP_VERSION_KEY = "version";
    const QString QMP_VERSION_ARRAY = "qemu";

    const QString QMP_VERSION_MAJOR = "major";
    const QString QMP_VERSION_MINOR = "minor";
    const QString QMP_VERSION_MICRO = "micro";

    QStringList keys = msg.keys();

    qDebug() << "Keys for the greetnig:" << keys;

    QJsonValue qmpVal = msg[QMP_GREETING_KEY];

    if (!qmpVal.isObject())
    {
        qWarning() << "QMP Greeting QMP Value not the expected object type";
        return;
    }

    QJsonObject qmpObj = qmpVal.toObject();

    if (!qmpObj.contains(QMP_VERSION_KEY) || !qmpObj[QMP_VERSION_KEY].isObject())
    {
        qWarning() << QMP_GREETING_KEY << "." << QMP_VERSION_KEY << "is not the expected object type";
        return;
    }

    QJsonObject greetingVerObj = qmpObj[QMP_VERSION_KEY].toObject();

    if (!greetingVerObj.contains(QMP_VERSION_ARRAY) || !greetingVerObj[QMP_VERSION_ARRAY].isObject())
    {
        qWarning() << QMP_GREETING_KEY << "." << QMP_VERSION_KEY << "." << QMP_VERSION_ARRAY <<  "is not the expected object type";
        return;
    }

    QJsonObject qemuVerObj = greetingVerObj[QMP_VERSION_ARRAY].toObject();

    int major, minor, micro;
    if ( !qemuVerObj.contains(QMP_VERSION_MAJOR) ||
         !qemuVerObj.contains(QMP_VERSION_MINOR) ||
         !qemuVerObj.contains(QMP_VERSION_MICRO) )
    {
        qWarning() << "Greeting parsing failed at major, minor, and micro version parsing";
        return;
    }

    major = qemuVerObj[QMP_VERSION_MAJOR].toInt(-1);
    minor = qemuVerObj[QMP_VERSION_MINOR].toInt(-1);
    micro = qemuVerObj[QMP_VERSION_MICRO].toInt(-1);

    qDebug() << QString("Qemu Version: %1.%2.%3").arg(major).arg(minor).arg(micro);



    // Now we need to send the QMP capabilities message to QEMU to enable remote control
    sendQmpCapabilities();
}

void QmpSocketMgr::handleQmpEvent(QJsonObject obj)
{
    // QMP events are defined as follows
    //  object obj {
    //    string event;
    //    object timestamp {
    //      int seconds;
    //      int microseconds;
    //    };
    //  };


    qDebug() << __PRETTY_FUNCTION__ << " Keys:" << obj.keys();

    if (!obj[EVENT_KEY].isString())
    {
        qWarning() << "QMP Event value is not the expected string type";
        return;
    }

    QString eventText = obj[EVENT_KEY].toString();

    if (!obj.contains(EVENT_TS_KEY) || !obj[EVENT_TS_KEY].isObject())
    {
        qWarning() << "QMP Event does not have the expected timestamp object";
        return;
    }

    QJsonObject ts = obj[EVENT_TS_KEY].toObject();

    if (!ts.contains(EVENT_TS_SECS) || !ts.contains(EVENT_TS_USECS))
    {
        qWarning() << "QMP event does not have the expected seconds and microseconds members in the timestamp event object";
        return;
    }

    int seconds = ts[EVENT_TS_SECS].toInt(0);
    int usecs   = ts[EVENT_TS_USECS].toInt(0);

    QString usecsPadding = "0";
    int numPaddingDigits = 6 - QString::number(usecs).length();

    QString displayText = QString("EVENT> %1.%2%3 %4").arg(seconds).arg(usecsPadding.repeated(numPaddingDigits)).arg(usecs).arg(eventText);

    qDebug() << displayText;

    emit eventReceived(eventText);
}

void QmpSocketMgr::handleQmpReturn(QJsonObject obj)
{
    qDebug() << __PRETTY_FUNCTION__ << " Keys:" << obj.keys();

    if (theState == QmpState::WAITING_FOR_CAPABILITY_RESPONSE)
    {
        qDebug() << "QEMU QMP interface ready (capability response received)";
        theState = QmpState::READY;
        return;
    }

    if (theState == QmpState::WAITING_FOR_RESPONSE)
    {
        qDebug() << "QEMU QMP response received";
        theState = QmpState::READY;
        return;
    }

    if (theState == QmpState::WAITING_FOR_HUMAN_COMMAND_RESPONSE)
    {
        qDebug() << "QEMU QMP human command response received!";

        if (obj["return"].isString())
        {
            emit humanResponseReceived(obj["return"].toString());
        }

        theState = QmpState::READY;
        return;
    }

    qWarning() << "Received an unexpected QEMU QMP Response";
}

void QmpSocketMgr::sendQmpCapabilities()
{
    const QString CAPABILITIES_VAL = "qmp_capabilities";

    QJsonObject msg;
    QJsonValue val(CAPABILITIES_VAL);
    msg.insert(EXECUTE_KEY, val);

    QJsonDocument doc;
    doc.setObject(msg);

    emit writeDataToSocket(doc.toJson(QJsonDocument::Compact));
    theState = QmpState::WAITING_FOR_CAPABILITY_RESPONSE;
}

bool QmpSocketMgr::sendNoParamNoRespCommand(QString command)
{
    if (theState != QmpState::READY)
    {
        qDebug() << "QEMU QMP interface not ready to send command:" << command;
        return false;
    }

    QJsonObject jo;
    QJsonValue cmdName(command);

    jo.insert(EXECUTE_KEY, cmdName);

    QJsonDocument jdoc;
    jdoc.setObject(jo);

    qDebug() << "About to send command (no parameter, no response):" << command;

    emit writeDataToSocket(jdoc.toJson(QJsonDocument::Compact));
    theState = QmpState::WAITING_FOR_RESPONSE;
    return true;
}
