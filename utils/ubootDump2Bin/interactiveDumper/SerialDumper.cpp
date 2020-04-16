#include "SerialDumper.h"
#include <QSerialPortInfo>
#include <QList>
#include <QMessageBox>
#include <QtDebug>
#include "mainwindow.h"

SerialDumper::SerialDumper(QObject *parent) : 
    QObject(parent),
    theGui(nullptr),
    theSerialPort(nullptr)
{
	
}

void SerialDumper::initMainWindow(MainWindow* mw)
{
	mw->populateSerialPortNames(getSerialPortList());
	
	if(!connect(mw, &MainWindow::openSerialPort,
	        this, &SerialDumper::openSerialPort))
	{
		qWarning() << "Connection for openSerialPort function failed in" << __PRETTY_FUNCTION__;
	}
	
	if(!connect(mw, &MainWindow::sendManualData,
	        this, &SerialDumper::sendSerialData))
	{
		qWarning() << "Connection for sendSerialData function failed in" << __PRETTY_FUNCTION__;
	}
	if(!connect(this, &SerialDumper::serialTextReceived,
	        mw, &MainWindow::serialTextReceived))
	{
		qWarning() << "Connection for serialTextReceived function failed in" << __PRETTY_FUNCTION__;
	}
	if(!connect(mw, &MainWindow::closeSerialPort,
	        this, &SerialDumper::closeSerialPort))	
	{
		qWarning() << "Connection for closeSerialPort function failed in" << __PRETTY_FUNCTION__;
	}
	
}

QStringList SerialDumper::getSerialPortList()
{
	QList<QSerialPortInfo> serPortInfos = QSerialPortInfo::availablePorts();
	
	QStringList retVal;
	foreach(QSerialPortInfo curPort, serPortInfos)
	{
		retVal.push_back(curPort.portName());
	}
	
	return retVal;
}

void SerialDumper::startDump(uint64_t address, uint32_t numBytes)
{
	
}

void SerialDumper::openSerialPort(QString name, 
                    QSerialPort::BaudRate baudRate, 
                    QSerialPort::DataBits dataBits, 
                    QSerialPort::FlowControl flowControl,
                    QSerialPort::StopBits stopBits,
                    QSerialPort::Parity parity)
{
	theSerialPort = new QSerialPort(name, this);
	if ( !theSerialPort->setBaudRate(baudRate) ||
	     !theSerialPort->setDataBits(dataBits) ||
	     !theSerialPort->setFlowControl(flowControl) ||
	     !theSerialPort->setStopBits(stopBits) ||
	     !theSerialPort->setParity(parity) ||
	     !theSerialPort->open(QIODevice::ReadWrite) )
	{
		QMessageBox::critical(theGui, "Error setting up serial port", "Error: " + theSerialPort->errorString());
		
		theSerialPort->deleteLater();
		theSerialPort = nullptr;
		return;
	}	
	
	qDebug() << "Serial port opened!";
	connect(theSerialPort, &QSerialPort::readyRead,
	        this, &SerialDumper::dataAvailable);
}

void SerialDumper::closeSerialPort()
{
	if (theSerialPort != nullptr)
	{
		qDebug() << "Serial port closed";
		theSerialPort->close();
		theSerialPort->deleteLater();
		theSerialPort = nullptr;
	}
}



void SerialDumper::stopDump()
{
	
}

void SerialDumper::sendSerialData(QString data)
{
	if (data.back() != '\n')
	{
		data.append('\n');
	}
	
	theSerialPort->write(data.toLatin1());
}

/**
 * Going to receive all the data and then split it into lines.  The split()
 * for QByteArray removes the delimiter.  I need to add it back, and track
 * if the last chunk requires it as well
 */
void SerialDumper::dataAvailable()
{
	if(theSerialPort->isReadable())
	{
		QByteArray text = theSerialPort->readAll();
		bool endWithNewLine = text.back() == '\n';
		
		// qDebug() << "Serial port Rx-ed" << text.length() << "bytes of data";
		
		QList<QByteArray> textLines = text.split('\n');
		
		for(int i = 0; i < textLines.length(); i++)
		{
			if (i == (textLines.length() - 1) )
			{
				// Last chunk
				if (endWithNewLine)
				{
					processSingleLine(textLines[i].append('\n'));
				}
				else
				{
					processSingleLine(textLines[i]);
				}
			}
			else
			{
				// Middle chunk
				processSingleLine(textLines[i].append('\n'));
			}
		}
		
	}
}

void SerialDumper::processSingleLine(QByteArray data)
{
	// qDebug() << "Going to process a line of " << data.length() << "bytes";
	
	if (!theOldData.isEmpty())
	{
		data = theOldData.append(data);
	}
	
	if (data.back() == '\n')
	{
		// qDebug() << "Full line: " << QString(data);
		
		// We have a full line to process!
		emit serialTextReceived(QString(data));
		theOldData.clear();
	}
	else
	{
		// Wait for the rest of the line to be received
		theOldData = data;
		
		// qDebug() << "theOldData is now" << theOldData.length() << "bytes long";
		// qDebug() << "the newline in it at" << theOldData.indexOf('\n');
		return;
	}
	
	/// @todo Process the data and convert into binary here
}


