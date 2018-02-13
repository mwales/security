#ifndef SOCKETCOMMANDINTERFACE_H
#define SOCKETCOMMANDINTERFACE_H

#include <QObject>
#include <QTcpSocket>
#include <QTimer>
#include <QJsonObject>

/**
 * This class manages the QMP socket interface.  All QMP messages use JSON serialization.  This
 * class doesn't do JSON serialization and deserialization for the caller, but it will peek inside
 * the data to see what type of JSON message was received when they come from QEMU
 */
class SocketCommandInterface : public QObject
{
    Q_OBJECT

public:
    SocketCommandInterface(QString host, int portNumber, QObject* parent = nullptr);

public slots:

    /**
     * Starts a timer that will handle connecting (and reconnecting) to the QMP socket server
     */
    void startConnection();

    /**
     * For the user to send raw data to the socket
     */
    void writeData(QString data);

    /**
     * Disconnect
     */
    void destroyConnection();

signals:

    /**
     * Error occured during operation
     */
    void errorMessage(QString msg);

    /**
     * Received JSON data from socket, the JSON object has a key "QMP" defined
     */
    void greetingMessage(QJsonObject obj);

    /**
     * Received JSON data from socket, the JSON object has a key "event" defined
     */
    void eventMessage(QJsonObject obj);

    /**
     * Received JSON data from socket, the JSON object has a key "return" defined
     */
    void returnMessage(QJsonObject obj);

protected slots:

    void socketConnected();

    void socketDisconnected();
    void socketError(QAbstractSocket::SocketError socketError);
    void socketDataReady();

    void trySocketConnection();

protected:

    // Seperate different Json objects from each other
    void preparseJsonData();

    void parseJsonData(QByteArray rawData);

    QTcpSocket* theSocket;

    bool theConnectedFlag;

    QTimer* theConnectTimer;

    QString theHostName;

    int thePortNumber;

    QByteArray theJsonDataStream;

};

#endif // SOCKETCOMMANDINTERFACE_H
