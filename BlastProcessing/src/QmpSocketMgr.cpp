#include "QmpSocketMgr.h"
#include "SocketCommandInterface.h"
#include <QJsonValue>
#include <QJsonArray>
#include <QJsonDocument>

#include <iostream>
#include <sstream>

const QString EXECUTE_KEY   = "execute";
const QString RETURN_KEY    = "return";
const QString ARGUMENTS_KEY = "arguments";

const QString EVENT_KEY  = "event";
const QString EVENT_TS_KEY = "timestamp";
const QString EVENT_TS_SECS = "seconds";
const QString EVENT_TS_USECS = "microseconds";

#ifdef QMP_SOCK_DEBUG
   #define QmpSockDebug     std::cout << "QMP_SOCK> "
   #define QmpSockWarn      std::cout << "QMP_SOCK> ** WARN ** "
#else
   #define QmpSockDebug     if(0) std::cout
   #define QmpSockWarn      if(0) std::cout
#endif

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

    QmpSockDebug << "Got here!" << std::endl;

    emit connectSocket();

    theState = QmpState::WAITING_FOR_GREETING;
}

QmpSocketMgr::~QmpSocketMgr()
{
    emit closeSocket();

    theSocketThread->exit();
    if (theSocketThread->wait(3000))
    {
        QmpSockDebug << "The socket thread exitted gracefully" << std::endl;
    }
    else
    {
        QmpSockWarn << "The socket thread didn't exit gracefully" << std::endl;
    }

    delete theSocketThread;

    delete theQmpSocket;


}

bool QmpSocketMgr::executeHumanMonitorCommand(QString cmd)
{
    QmpSockDebug << __PRETTY_FUNCTION__ << "(" << cmd.toStdString() << ")" << std::endl;

    if (theState != QmpState::READY)
    {
        if (theState == QmpState::NOT_CONNECTED)
        {
            QmpSockDebug << "QEMU QMP interface not ready to send human monitor command:"
                         << cmd.toStdString() << std::endl;
            return false;
        }
        else
        {
            QmpSockDebug << "Other command in process, HMI command (" << cmd.toStdString()
                         << ") will be enqueued" << std::endl;
            QPair< QueuedCommandType, QString> qe;
            qe.first = QueuedCommandType::HUMAN_MONITOR_COMMAND;
            qe.second = cmd;

            theQueue.push_back(qe);
            return true;
        }
    }

    QJsonObject jo;
    QJsonValue cmdName("human-monitor-command");

    jo.insert(EXECUTE_KEY, cmdName);

    QJsonObject argObj;
    argObj.insert("command-line", QJsonValue(cmd));

    jo.insert(ARGUMENTS_KEY, argObj);

    QJsonDocument jdoc;
    jdoc.setObject(jo);

    QmpSockDebug << "About to send human monitor command" << std::endl;

    emit writeDataToSocket(jdoc.toJson(QJsonDocument::Compact));
    theState = QmpState::WAITING_FOR_HUMAN_COMMAND_RESPONSE;
    return true;
}

bool QmpSocketMgr::enableVnc()
{
    QmpSockDebug << __PRETTY_FUNCTION__ << std::endl;
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
    QmpSockDebug << __PRETTY_FUNCTION__ << "(" << filename.toStdString() << ")" << std::endl;

    if (theState != QmpState::READY)
    {
        if (theState == QmpState::NOT_CONNECTED)
        {
            QmpSockWarn << "QEMU QMP interface not ready to send screendump command" << std::endl;
            return false;
        }
        else
        {
            QmpSockDebug << "Other command in process, screendump (" << filename.toStdString()
                         << ") will be enqueued" << std::endl;
            QPair< QueuedCommandType, QString> qe;
            qe.first = QueuedCommandType::SCREENDUMP;
            qe.second = filename;

            theQueue.push_back(qe);
            return true;
        }
    }

    QJsonObject jo;
    QJsonValue cmdName("screendump");

    jo.insert(EXECUTE_KEY, cmdName);

    QJsonObject argObj;
    argObj.insert("filename", QJsonValue(filename));

    jo.insert(ARGUMENTS_KEY, argObj);

    QJsonDocument jdoc;
    jdoc.setObject(jo);

    QmpSockDebug << "About to send screedump command" << std::endl;

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
    QmpSockDebug << __PRETTY_FUNCTION__ << "(" << snapshotName.toStdString() << ")" << std::endl;
    return false;
}

QString QmpSocketMgr::querySnapshots()
{
    return "";
}

bool QmpSocketMgr::loadSnapshot(QString snapshotName)
{
    QmpSockDebug << __PRETTY_FUNCTION__ << "(" << snapshotName.toStdString() << ")" << std::endl;
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

    QmpSockDebug << "Keys for the greetnig: " << keys.join(',').toStdString() << std::endl;

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

    QmpSockDebug << QString("Qemu Version: %1.%2.%3").arg(major).arg(minor).arg(micro).toStdString() << std::endl;



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


    QmpSockDebug << __PRETTY_FUNCTION__ << " Keys:" << obj.keys().join(',').toStdString() << std::endl;

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

    QmpSockDebug << displayText.toStdString() << std::endl;

    emit eventReceived(eventText);
}

void QmpSocketMgr::handleQmpReturn(QJsonObject obj)
{
    QmpSockDebug << __PRETTY_FUNCTION__ << " Keys:" << obj.keys().join(',').toStdString() << std::endl;

    if (theState == QmpState::WAITING_FOR_CAPABILITY_RESPONSE)
    {
        QmpSockDebug << "QEMU QMP interface ready (capability response received)" << std::endl;
        theState = QmpState::READY;

        emit qmpInterfaceReady();

        dequeRemainingCommands();
        return;
    }

    if (theState == QmpState::WAITING_FOR_RESPONSE)
    {
        QmpSockDebug << "QEMU QMP response received" << std::endl;
        theState = QmpState::READY;

        dequeRemainingCommands();
        return;
    }

    if (theState == QmpState::WAITING_FOR_HUMAN_COMMAND_RESPONSE)
    {
        QmpSockDebug << "QEMU QMP human command response received!" << std::endl;

        if (obj["return"].isString())
        {
            emit humanResponseReceived(obj["return"].toString());
        }

        theState = QmpState::READY;

        dequeRemainingCommands();
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
        if (theState == QmpState::NOT_CONNECTED)
        {
            QmpSockWarn << "QEMU QMP interface not ready to send command:" << command.toStdString() << std::endl;
            return false;
        }
        else
        {
            QmpSockDebug << "Other command in process, command (" << command.toStdString() 
                         << ") will be enqueued" << std::endl;
            QPair< QueuedCommandType, QString> qe;
            qe.first = QueuedCommandType::NO_RESPONSE_QMP;
            qe.second = command;

            theQueue.push_back(qe);
            return true;
        }
    }

    QJsonObject jo;
    QJsonValue cmdName(command);

    jo.insert(EXECUTE_KEY, cmdName);

    QJsonDocument jdoc;
    jdoc.setObject(jo);

    QmpSockDebug << "About to send command (no parameter, no response):" << command.toStdString() << std::endl;

    emit writeDataToSocket(jdoc.toJson(QJsonDocument::Compact));
    theState = QmpState::WAITING_FOR_RESPONSE;
    return true;
}

void QmpSocketMgr::dequeRemainingCommands()
{
    if (!theQueue.empty())
    {
        QPair<QueuedCommandType, QString> qe;
        qe = theQueue.first();

        theQueue.pop_front();

        switch(qe.first)
        {
        case QueuedCommandType::HUMAN_MONITOR_COMMAND:
            QmpSockDebug << "Dequeued a HUMAN_MONITOR_COMMAND:" << qe.second.toStdString() << std::endl;
            executeHumanMonitorCommand(qe.second);
            return;

        case QueuedCommandType::ENABLE_VNC:
            QmpSockWarn << "Unsupported queued command type" << std::endl;
            return;

        case QueuedCommandType::DISABLE_VNC:
            QmpSockWarn << "Unsupported queued command type" << std::endl;
            return;

        case QueuedCommandType::QUERY_VNC:
            QmpSockWarn << "Unsupported queued command type" << std::endl;
            return;

        case QueuedCommandType::SCREENDUMP:
            QmpSockDebug << "Dequeued a SCREENDUMP command, filename:" << qe.second.toStdString() << std::endl;
            screendump(qe.second);
            return;

        case QueuedCommandType::NO_RESPONSE_QMP:
            QmpSockDebug << "Dequeued a NO_RESPONSE_QMP command:" << qe.second.toStdString() << std::endl;
            sendNoParamNoRespCommand(qe.second);
            return;

        case QueuedCommandType::SAVE_SNAPSHOT:
            QmpSockWarn << "Unsupported queued command type" << std::endl;
            return;

        case QueuedCommandType::LOAD_SNAPSHOT:
            QmpSockWarn << "Unsupported queued command type" << std::endl;
            return;
        default:
            QmpSockWarn << "Invalid queued command type" << std::endl;
        }
    }
}
