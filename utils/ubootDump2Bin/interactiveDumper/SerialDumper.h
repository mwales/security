#ifndef SERIALDUMPER_H
#define SERIALDUMPER_H

#include <QObject>
#include <QSerialPort>

class MainWindow;
class QSerialPort;

class SerialDumper : public QObject
{
	Q_OBJECT
public:
	explicit SerialDumper(QObject *parent = nullptr);
	
	void initMainWindow(MainWindow* mw);
	
	QStringList getSerialPortList();
	
signals:
	
	void updateProgress(int curProgress, int finalProgress);
	
	void dumpComplete();
	
	void serialTextReceived(QString text);
	
public slots:
	
	void startDump(uint64_t address, uint32_t numBytes);
	
	void openSerialPort(QString name, 
	                    QSerialPort::BaudRate baudRate, 
	                    QSerialPort::DataBits dataBits, 
	                    QSerialPort::FlowControl flowControl,
	                    QSerialPort::StopBits stopBits,
	                    QSerialPort::Parity parity);
	
	void closeSerialPort();
	
	void stopDump();
	
	void sendSerialData(QString data);
	
protected slots:
	
	void dataAvailable();
	
	
	
protected:
	
	void processSingleLine(QByteArray data);
	
	MainWindow* theGui;
	
	QSerialPort* theSerialPort;
	
	QByteArray theOldData;
};

#endif // SERIALDUMPER_H
