#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QVector>
#include <QString>
#include <QMap>
#include <stdint.h>
#include <QSerialPort>
#include <QTime>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
	Q_OBJECT
	
public:
	explicit MainWindow(QWidget *parent = nullptr);
	~MainWindow();
	
	void populateSerialPortNames(QStringList const & names);
	
signals:
	
	void startDumping(uint64_t address, uint32_t numBytes, QString filename,
	                  QString crcCmd, QString dumpCommand);
	
	void openSerialPort(QString name, 
	                    QSerialPort::BaudRate baudRate, 
	                    QSerialPort::DataBits dataBits, 
	                    QSerialPort::FlowControl flowControl,
	                    QSerialPort::StopBits stopBits,
	                    QSerialPort::Parity parity);
	
	void closeSerialPort();
	
	void abortDump();
	
	void sendManualData(QString data);
	
public slots:
	
	void serialTextReceived(QString data);
	
	void updateProgress(int currentVal, int maxValue);
	
	void dumpFinished(QString completeMsg);
	
protected slots:
	
	void serialButtonPressed();
	
	void dumpButtonPressed();
	
	void portClosed();
	
	void manualCmdButtonPressed();
	
private:
	Ui::MainWindow *ui;
	
protected:
	
	int theMaxProgressValue;
	
	bool thePortOpen;
	
	bool theDumpInProgress;
	
	QMap<QString, QSerialPort::BaudRate> theBaudRateMap;
	QMap<QString, QSerialPort::DataBits> theDataBitsMap;
	QMap<QString, QSerialPort::FlowControl> theFlowControlMap;
	QMap<QString, QSerialPort::StopBits> theStopBitsMap;
	QMap<QString, QSerialPort::Parity> theParityMap;
	
	QTime theDumpTimer;
};

#endif // MAINWINDOW_H
