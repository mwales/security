#include "SocketCommandInterface.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QJsonValue>

SocketCommandInterface::SocketCommandInterface(QString host, int portNumber, QObject* parent):
    theSocket(nullptr),
    theConnectedFlag(false),
    theConnectTimer(nullptr),
    theHostName(host),
    thePortNumber(portNumber)
{
    qDebug() << __PRETTY_FUNCTION__;

    theSocket = new QTcpSocket(this);

    connect(theSocket, SIGNAL(connected()),
            this, SLOT(socketConnected()));
    connect(theSocket, &QTcpSocket::disconnected,
            this, &SocketCommandInterface::socketDisconnected);
    connect(theSocket, SIGNAL(error(QAbstractSocket::SocketError)),
            this, SLOT(socketError(QAbstractSocket::SocketError)));
    connect(theSocket, SIGNAL(readyRead()),
            this, SLOT(socketDataReady()));

    theConnectTimer = new QTimer(this);
    connect(theConnectTimer, &QTimer::timeout,
            this, &SocketCommandInterface::trySocketConnection);

}

void SocketCommandInterface::startConnection()
{
    qDebug() << "About to start connection timer";

    theConnectTimer->setSingleShot(true);
    theConnectTimer->start(1000);
}

void SocketCommandInterface::writeData(QString data)
{
    qDebug() << "Write: " << data;
}

void SocketCommandInterface::destroyConnection()
{
    if (theConnectedFlag)
    {
        theSocket->close();
        theSocket->waitForDisconnected();
    }
}

void SocketCommandInterface::socketConnected()
{
    qDebug() << "QMP Connected";
    theConnectedFlag = true;
}

void SocketCommandInterface::socketDisconnected()
{
    qDebug() << "QMP Disconnected";
    theConnectedFlag = false;
}

void SocketCommandInterface::socketError(QAbstractSocket::SocketError socketError)
{
    QString errMsg;

    switch(socketError)
    {
    case QAbstractSocket::ConnectionRefusedError:
        errMsg = "The connection was refused by the peer (or timed out).";
        break;
    case QAbstractSocket::RemoteHostClosedError:
        errMsg = "The remote host closed the connection. Note that the client socket (i.e., this socket) will be closed after the remote close notification has been sent.";
        break;
    case QAbstractSocket::HostNotFoundError:
        errMsg = "The host address was not found.";
        break;
    case QAbstractSocket::SocketAccessError:
        errMsg = "The socket operation failed because the application lacked the required privileges.";
        break;
    case QAbstractSocket::SocketResourceError:
        errMsg = "The local system ran out of resources (e.g., too many sockets).";
        break;
    case QAbstractSocket::SocketTimeoutError:
        errMsg = "The socket operation timed out.";
        break;
    case QAbstractSocket::DatagramTooLargeError:
        errMsg = "The datagram was larger than the operating system's limit (which can be as low as 8192 bytes).";
        break;
    case QAbstractSocket::NetworkError:
        errMsg = "An error occurred with the network (e.g., the network cable was accidentally plugged out).";
        break;
    case QAbstractSocket::AddressInUseError:
        errMsg = "The address specified to QAbstractSocket::bind() is already in use and was set to be exclusive.";
        break;
    case QAbstractSocket::SocketAddressNotAvailableError:
        errMsg = "The address specified to QAbstractSocket::bind() does not belong to the host.";
        break;
    case QAbstractSocket::UnsupportedSocketOperationError:
        errMsg = "The requested socket operation is not supported by the local operating system (e.g., lack of IPv6 support).";
        break;
    case QAbstractSocket::ProxyAuthenticationRequiredError:
        errMsg = "The socket is using a proxy, and the proxy requires authentication.";
        break;
    case QAbstractSocket::SslHandshakeFailedError:
        errMsg = "The SSL/TLS handshake failed, so the connection was closed (only used in QSslSocket)";
        break;
    case QAbstractSocket::UnfinishedSocketOperationError:
        errMsg = "Used by QAbstractSocketEngine only, The last operation attempted has not finished yet (still in progress in the background).";
        break;
    case QAbstractSocket::ProxyConnectionRefusedError:
        errMsg = "Could not contact the proxy server because the connection to that server was denied";
        break;
    case QAbstractSocket::ProxyConnectionClosedError:
        errMsg = "The connection to the proxy server was closed unexpectedly (before the connection to the final peer was established)";
        break;
    case QAbstractSocket::ProxyConnectionTimeoutError:
        errMsg = "The connection to the proxy server timed out or the proxy server stopped responding in the authentication phase.";
        break;
    case QAbstractSocket::ProxyNotFoundError:
        errMsg = "The proxy address set with setProxy() (or the application proxy) was not found.";
        break;
    case QAbstractSocket::ProxyProtocolError:
        errMsg = "The connection negotiation with the proxy server failed, because the response from the proxy server could not be understood.";
        break;
    case QAbstractSocket::OperationError:
        errMsg = "An operation was attempted while the socket was in a state that did not permit it.";
        break;
    case QAbstractSocket::SslInternalError:
        errMsg = "The SSL library being used reported an internal error. This is probably the result of a bad installation or misconfiguration of the library.";
        break;
    case QAbstractSocket::SslInvalidUserDataError:
        errMsg = "Invalid data (certificate, key, cypher, etc.) was provided and its use resulted in an error in the SSL library.";
        break;
    case QAbstractSocket::TemporaryError:
        errMsg = "A temporary error occurred (e.g., operation would block and socket is non-blocking).";
        break;
    case QAbstractSocket::UnknownSocketError:
    default:
        errMsg = "An unidentified error occurred.";
    }

    qWarning() << "QEMU QMP Error: " << errMsg;
    emit errorMessage(errMsg);

    if (!theConnectedFlag)
    {
        // The socket error means we weren't connected yet, but failed connection attempt.  Try
        // again in a few seconds
        theConnectTimer->start(3000);
    }
}

void SocketCommandInterface::socketDataReady()
{
    QByteArray newData = theSocket->readAll();
    qDebug() << "Socket Data:" << newData;

    theJsonDataStream.append(newData);

    preparseJsonData();
}

void SocketCommandInterface::trySocketConnection()
{
    if (theConnectedFlag)
    {
        qDebug() << "trySocketConnection called, but we are already connected!";
        theConnectTimer->stop();
    }
    else
    {
        theSocket->connectToHost(theHostName, thePortNumber);
    }
}

void SocketCommandInterface::preparseJsonData()
{
    QByteArray rawData;
    int countOfOpenSquiglys = 0;
    int countOfOpenBrackets = 0;

    bool inString = false;
    for(int i = 0; i < theJsonDataStream.length(); i++)
    {
        char thisByte = theJsonDataStream[i];
        rawData.append(thisByte);

        if (inString)
        {
            // Squiglys and brackets don't count if they are in a string
            if (thisByte == '"')
            {
                inString = false;
                //qDebug() << "Ending string at" << i;
            }

            if (thisByte == '\'')
            {
                //qDebug() << "Found an escape character at" << i;

                // An escape sequence, GASP!  We will need to read the next character
                i++;
                if (i >= theJsonDataStream.length())
                {
                    // We will need more data, exit for now...
                    return;
                }

                // We know something is escaped, but don't really care what it is, just add it into
                // the dat stream and keep on trucking
                rawData.append(theJsonDataStream[i]);
            }

            // If we get here, it was just regular string data
            continue;
        }

        if (thisByte == '"')
        {
            inString = true;
            //qDebug() << "Starting string at" << i;
            continue;
        }

        if (thisByte == '{')
        {
            countOfOpenSquiglys++;
            continue;
        }

        if (thisByte == '[')
        {
            countOfOpenBrackets++;
            continue;
        }

        // Flag to denote possible end of JSON data
        bool termChar = false;
        if (thisByte == '}')
        {
            if (countOfOpenSquiglys > 0)
            {
                countOfOpenSquiglys--;
                termChar = true;
            }
            else
            {
                qWarning() << "Invalid JSON data.  Found a } without opening { at byte"
                           << i << "in data stream";
            }
        }

        if (thisByte == ']')
        {
            if (countOfOpenBrackets > 0)
            {
                countOfOpenBrackets--;
                termChar = true;
            }
            else
            {
                qWarning() << "Invalid JSON data.  Found a ] without opening [ at byte"
                           << i << "in data stream";
            }
        }

        if ( termChar &&
             (countOfOpenBrackets == 0) &&
             (countOfOpenSquiglys == 0) )
        {
            // End of JSON data in the stream, send this to the proper JSON parser!
            parseJsonData(rawData);

            // Keep on parsing, but reset the stream of raw data
            theJsonDataStream.remove(0, i+1);
            rawData.clear();
            i = 0;
        }

    }
}

void SocketCommandInterface::parseJsonData(QByteArray rawData)
{
    qDebug() << "parseJsonData:" << rawData;

    QJsonParseError err;
    QJsonDocument jd = QJsonDocument::fromJson(rawData, &err);

    if (jd.isNull())
    {
        qWarning() << "JSON Data invalid!";
        qWarning() << "  Parser:" << err.errorString();
        return;
    }

    if (jd.isArray())
    {
        qWarning() << "JSON Data is an array, not handled!";
        return;
    }

    if (jd.isEmpty())
    {
        qDebug() << "JSON Data is empty, weird...";
        return;
    }

    if (!jd.isObject())
    {
        qWarning() << "JSON Data isn't an object!?!";
        return;
    }

    QJsonObject jo = jd.object();

    if (jo.contains("QMP"))
    {
        qDebug() << "Handle server greeting";
        processServerGreeting(jo);
        return;
    }

    if (jo.contains("event"))
    {
        qDebug() << "Handle event";
        return;
    }

    if (jo.contains("return"))
    {
        qDebug() << "Handle response";
        return;
    }

    qWarning() << "Received a JSON object, but don't know how to parse!";




}

void SocketCommandInterface::processServerGreeting(QJsonObject const & msg)
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




}
