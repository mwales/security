#ifndef SOCKETCOMMANDINTERFACE_H
#define SOCKETCOMMANDINTERFACE_H

#include <QObject>
#include <QTcpSocket>
#include <QTimer>

class SocketCommandInterface : public QObject
{
    Q_OBJECT

public:
    SocketCommandInterface(QString host, int portNumber, QObject* parent = nullptr);



public slots:

    void startConnection();

    void writeData(QString data);

    void destroyConnection();

signals:

    void errorMessage(QString msg);

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
