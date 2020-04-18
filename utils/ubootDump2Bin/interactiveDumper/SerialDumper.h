#ifndef SERIALDUMPER_H
#define SERIALDUMPER_H

#include <QObject>
#include <QSerialPort>
#include <QFile>
#include <QTimer>

class MainWindow;
class QSerialPort;

enum DumpingState
{
	START_DUMP,
	START_DUMP_BLOCK,
	READING_DUMP_DATA,
	START_DUMP_CRC,
	READING_DUMP_CRC,
	NOT_DUMPING
};

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
	
	void startDump(uint64_t address, uint32_t numBytes, QString filename,
	               QString ubootPrompt, QString dumpCommand);
	
	void openSerialPort(QString name, 
	                    QSerialPort::BaudRate baudRate, 
	                    QSerialPort::DataBits dataBits, 
	                    QSerialPort::FlowControl flowControl,
	                    QSerialPort::StopBits stopBits,
	                    QSerialPort::Parity parity);
	
	void closeSerialPort();
	
	void stopDump();
	
	void sendSerialData(QString data);
	
	void blockTimerFired();
	
protected slots:
	
	void dataAvailable();	
	
protected:
	
	bool isHexChar(QChar x);
	
	bool isHexString(QString s);
	
	QByteArray processDumpText(QString dumpData);
	
	void processSingleLine(QByteArray data);
	
	// State machine methods
	void executeState();
	void executeStartDumpState();
	void executeStartDumpBlockState();
	void executeReadingDumpDataState();
	void executeStartDumpCrcState();
	void executeReadingDumpCrcState();
	void executeNotDumpingState();
	
	QString currentStateName();
	
	MainWindow* theGui;
	
	QSerialPort* theSerialPort;
	
	QByteArray theOldData;
	
	uint64_t theCurrentDumpAddress;
	
	uint64_t theCurrentDumpBlockAddr;
	
	QByteArray theCurrentDumpBlock;
	
	uint64_t theCurrentBlockSize;
	
	uint64_t theCurrentNumBytes;
	
	uint32_t theFinalDumpSize;
	
	QFile theOutputFile;
	
	enum DumpingState theCurrentState;
	
	QString theDumpFilename;
	
	QString thePrompt;
	
	QString theDumpCommand;
	
	QTimer theBlockTimer;
	
	uint32_t theNumTimerFiringsForOneBlock;
};

#endif // SERIALDUMPER_H
