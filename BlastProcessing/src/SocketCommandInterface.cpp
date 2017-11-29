#include "SocketCommandInterface.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QJsonValue>

#include <iostream>

#ifdef SOCK_CMD_DEBUG
   #define SockCmdDebug     std::cout << "SOCK_CMD> "
   #define SockCmdWarn      std::cout << "SOCK_CMD> ** WARN ** "
#else
   #define SockCmdDebug     if(0) std::cout
   #define SockCmdWarn      if(0) std::cout
#endif

SocketCommandInterface::SocketCommandInterface(QString host, int portNumber, QObject* parent):
    QObject(parent),
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
    SockCmdDebug << "About to start connection timer" << std::endl;

    theConnectTimer->setSingleShot(true);
    theConnectTimer->start(1000);
}

void SocketCommandInterface::writeData(QString data)
{
    SockCmdDebug << "Write: " << data.toStdString() << std::endl;

    theSocket->write(data.toStdString().c_str(), data.length());
}

void SocketCommandInterface::destroyConnection()
{
    SockCmdDebug << __PRETTY_FUNCTION__ << "Not sure if this is a good idea as a regular function" << std::endl;

    switch(theSocket->state())
    {
    case QAbstractSocket::UnconnectedState:
        SockCmdDebug << "Socket state is unconnected" << std::endl;
        break;

    case QAbstractSocket::HostLookupState:
        SockCmdDebug << "Socket state is HostLookupState" << std::endl;
        break;

    case QAbstractSocket::ConnectingState:
        SockCmdDebug << "Socket state is ConnectingState" << std::endl;
        break;

    case QAbstractSocket::ConnectedState:
        SockCmdDebug << "Socket state is ConnectedState" << std::endl;
        break;

    case QAbstractSocket::BoundState:
        SockCmdDebug << "Socket state is BoundState" << std::endl;
        break;

    case QAbstractSocket::ClosingState:
        SockCmdDebug << "Socket state is ClosingState" << std::endl;
        break;

    case QAbstractSocket::ListeningState:
        SockCmdDebug << "Socket state is ListeningState" << std::endl;
        break;

    default:
        SockCmdWarn << "Completely invalid socket state returned in " << __PRETTY_FUNCTION__ << std::endl;
    }


    if (theConnectedFlag)
    {
        theSocket->close();
        theSocket->waitForDisconnected();
    }
}

void SocketCommandInterface::socketConnected()
{
    SockCmdDebug << "QMP Connected" << std::endl;
    theConnectedFlag = true;
}

void SocketCommandInterface::socketDisconnected()
{
    SockCmdDebug << "QMP Disconnected" << std::endl;
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

    SockCmdWarn << "QEMU QMP Error: " << errMsg.toStdString() << std::endl;
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
    SockCmdDebug << "Socket Data:" << newData.data() << std::endl;

    theJsonDataStream.append(newData);

    preparseJsonData();
}

void SocketCommandInterface::trySocketConnection()
{
    if (theConnectedFlag)
    {
        SockCmdDebug << "trySocketConnection called, but we are already connected!" << std::endl;
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
                SockCmdWarn << "Invalid JSON data.  Found a } without opening { at byte "
                            << i << "in data stream" << std::endl;
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
                SockCmdWarn << "Invalid JSON data.  Found a ] without opening [ at byte"
                            << i << "in data stream" << std::endl;
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
    SockCmdDebug << "parseJsonData:" << rawData.data() << std::endl;

    QJsonParseError err;
    QJsonDocument jd = QJsonDocument::fromJson(rawData, &err);

    if (jd.isNull())
    {
        SockCmdWarn << "JSON Data invalid!" << std::endl;
        SockCmdWarn << "  Parser:" << err.errorString().toStdString() << std::endl;
        return;
    }

    if (jd.isArray())
    {
        SockCmdWarn << "JSON Data is an array, not handled!" << std::endl;
        return;
    }

    if (jd.isEmpty())
    {
        SockCmdDebug << "JSON Data is empty, weird..." << std::endl;
        return;
    }

    if (!jd.isObject())
    {
        SockCmdWarn << "JSON Data isn't an object!?!" << std::endl;
        return;
    }

    QJsonObject jo = jd.object();

    if (jo.contains("QMP"))
    {
        SockCmdDebug << "Handle server greeting" << std::endl;
        emit greetingMessage(jo);
        return;
    }

    if (jo.contains("event"))
    {
        SockCmdDebug << "Handle event" << std::endl;
        emit eventMessage(jo);
        return;
    }

    if (jo.contains("return"))
    {
        SockCmdDebug << "Handle response" << std::endl;
        emit returnMessage(jo);
        return;
    }

    SockCmdWarn << "Received a JSON object, but don't know how to parse!" << std::endl;


}

