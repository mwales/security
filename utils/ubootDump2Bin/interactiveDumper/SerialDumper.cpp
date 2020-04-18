#include "SerialDumper.h"
#include <QSerialPortInfo>
#include <QList>
#include <QMessageBox>
#include <QtDebug>
#include "mainwindow.h"

const int TIMER_FIRE_PERIOD = 2000;
const int BLOCK_SIZE = 256;

SerialDumper::SerialDumper(QObject *parent) : 
    QObject(parent),
    theGui(nullptr),
    theSerialPort(nullptr),
    theCurrentDumpAddress(0),
    theCurrentDumpBlockAddr(0),
    theCurrentNumBytes(0),
    theFinalDumpSize(0),
    theOutputFile(this),
    theCurrentState(NOT_DUMPING),
    theBlockTimer(this),
    theNumTimerFiringsForOneBlock(0)
{
	theBlockTimer.setInterval(TIMER_FIRE_PERIOD);
	connect(&theBlockTimer, &QTimer::timeout,
	        this, &SerialDumper::blockTimerFired);
	theBlockTimer.start();
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
	
	if (!connect(mw, &MainWindow::closeSerialPort,
	             this, &SerialDumper::closeSerialPort))
	{
		qWarning() << "Connection for closeSerialPort function failed in" << __PRETTY_FUNCTION__;
	}
	
	if (!connect(mw, &MainWindow::startDumping,
	             this, &SerialDumper::startDump))
	{
		qWarning() << "Connection for startDump function failed in" << __PRETTY_FUNCTION__;
	}
	
	if (!connect(mw, &MainWindow::abortDump,
	             this, &SerialDumper::stopDump))
	{
		qWarning() << "Connection for stopDump function failed in" << __PRETTY_FUNCTION__;
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

void SerialDumper::startDump(uint64_t address, uint32_t numBytes, QString filename,
                             QString prompt, QString command)
{
	if (theCurrentState != NOT_DUMPING)
	{
		QMessageBox::critical(theGui, "Invalid state to start dump",
		                      currentStateName() + " invalid state to start dumping");
		return;
	}
	
	theCurrentDumpAddress = address;
	theFinalDumpSize = numBytes;
	theCurrentNumBytes = 0;
	theDumpFilename = filename;
	thePrompt = prompt;
	theDumpCommand = command;
	
	theCurrentState = START_DUMP;
	executeState();
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
	if (theCurrentState == NOT_DUMPING)
	{
		QMessageBox::critical(theGui, "Invalid state to stop dumping",
		                      currentStateName() + " invalid state to stop dumping");
		return;
	}
	
	theCurrentState = NOT_DUMPING;
	executeState();
}

void SerialDumper::sendSerialData(QString data)
{
	if (data.back() != '\n')
	{
		data.append('\n');
	}
	
	theSerialPort->write(data.toLatin1());
}

void SerialDumper::blockTimerFired()
{
	// Are we dumping a block right now?
	if ( (theCurrentState != READING_DUMP_DATA) &&
	     (theCurrentState != READING_DUMP_CRC) )
	{
		qDebug() << "Current state" << currentStateName() << "don't have timeout conditions";
		return;
	}
	
	// Increase fire count
	theNumTimerFiringsForOneBlock++;
	
	
	if (theNumTimerFiringsForOneBlock < 2)
	{
		qDebug() << "Timer fired while waiting in" << currentStateName();		
		// We are waiting for the CRC to complete, but haven't fired twice
		return;
	}
		
	// We timed out waiting for something!
		
	if (theCurrentState == READING_DUMP_CRC)
	{
		qDebug() << "Timeout while waiting for CRC";
		emit serialTextReceived("Dumper>Timeout while waiting for CRC\n");
		theCurrentState = START_DUMP_CRC;
		executeState();
		return;
	}
	
	// If we got here, we were waiting for a block, 
	qDebug() << "Timeout while waiting for Data Block";
	emit serialTextReceived("Dumper>Timeout while waiting for Data Block\n");
	theCurrentState = START_DUMP_BLOCK;
	executeState();
	return;
	
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
		
		executeState();
		
	}
}

bool SerialDumper::isHexChar(QChar x)
{
	if ( (x >= '0') && (x <= '9'))
		return 1;	
	
	if ( (x >= 'a') && (x <= 'f'))
		return 1;
	
	if ( (x >= 'A') && (x <= 'F') )
		return 1;
	
	return 0;
}

bool SerialDumper::isHexString(QString s)
{
	foreach(QChar curChar, s)
	{
		if (!isHexChar(curChar))
		{
			return false;
		}
	}
	
	return true;
}

QByteArray SerialDumper::processDumpText(QString dumpData)
{
	dumpData = dumpData.trimmed();
	
	qDebug() << __PRETTY_FUNCTION__ << " called with: " << dumpData;
	
	QStringList tokens = dumpData.split(QRegExp("[: ]+"));
	qDebug() << "Token List: " << tokens;
	
	// There needs to be 18 tokens: address, 16 bytes, ascii
	if (tokens.length() < 18)
	{
		qDebug() << "  process failed, not enough tokens (" << tokens.length() << ")";
		return QByteArray();
	}
	
	// Make sure the first 17 tokens are the correct length:  address and 16 bytes
	if (tokens.at(0).length() != 8)
	{
		qDebug() << "  addresss token the wrong size [" << tokens.at(0) << "], with len="
		         << tokens.at(0).length();
		return QByteArray();
	}
	
	for(int i = 1; i <= 16; i++)
	{
		if (tokens.at(i).length() != 2)
		{
			qDebug() << "  process failed, data token " << i << " wrong size";
			qDebug() << " token [" << tokens.at(i) << "], with len="
			         << tokens.at(i).length();
			return QByteArray();
		}
	}
	
	// All the first 17 tokens must be hex
	for(int i = 0; i < 17; i++)
	{
		if (!isHexString(tokens.at(i)))
		{
			qDebug() << "  process failed, data token text not hex";
			return QByteArray();
		}
	}
	
	unsigned long temp[17];
	for(int i = 0; i < 17; i++)
	{
		temp[i] = tokens.at(i).toULong(nullptr, 16);
	}
	
	/*
	uint64_t addressOfText = 0xffffffff & temp[0];
	
	if ( (addressOfText != theCurrentDumpAddress) &&
	     ( (addressOfText - theCurrentDumpAddress < 0x80)) )
	{
		qDebug() << "Looking for address " << QString::number(theCurrentDumpAddress,16) 
		         << " but we found address " << QString::number(addressOfText,16) 
		         << " instead";
	}
	
	if (addressOfText != theCurrentDumpAddress)
	{
		qDebug() << "  process failed, wrong address: " << QString::number(addressOfText,16) 
		       << "!=" << QString::number(theCurrentDumpAddress,16);
		return QByteArray();
	}
	*/
	
	QByteArray retVal;
	for(int i = 1; i <= 16; i++)
	{
		retVal.append( static_cast<char>(temp[i] & 0xff) );
	}
	
	//theCurrentDumpAddress += 0x10;
	
	
	return retVal;
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
	
	theCurrentDumpBlock.append(processDumpText(QString(data)));
}

void SerialDumper::executeState()
{
	qDebug() << "executeState() called for" << currentStateName() << "state";
	
	switch(theCurrentState)
	{
	case START_DUMP:
		executeStartDumpState();
		return;
		
	case START_DUMP_BLOCK:
		executeStartDumpBlockState();
		return;
		
	case READING_DUMP_DATA:
		executeReadingDumpDataState();
		return;
		
	case START_DUMP_CRC:
		executeStartDumpCrcState();
		return;
		
	case READING_DUMP_CRC:
		executeReadingDumpCrcState();
		return;
		
	case NOT_DUMPING:
		executeNotDumpingState();
		return;
	}
}

void SerialDumper::executeStartDumpState()
{
	theOutputFile.setFileName(theDumpFilename);
	if (!theOutputFile.open(QIODevice::WriteOnly))
	{
		QMessageBox::critical(theGui, "Error saving file",
		                      theOutputFile.errorString());
		return;
	}
	
	qDebug() << theDumpFilename << "opened for dumping";
	
	// Track dump start address
	theCurrentDumpBlockAddr = theCurrentDumpAddress;
	theCurrentNumBytes = 0;
	
	emit updateProgress(static_cast<int>(theCurrentNumBytes),
	                    static_cast<int>(theFinalDumpSize));
	
	theCurrentState = START_DUMP_BLOCK;
	executeState();
}

void SerialDumper::executeStartDumpBlockState()
{
	// Reset the timeout firing count to 0
	theNumTimerFiringsForOneBlock = 0;
	
	theCurrentDumpBlock.clear();
	theOldData.clear();
	
	// Prepare the command
	theCurrentBlockSize = BLOCK_SIZE;
	uint64_t numBytesLeftInDump = theCurrentDumpAddress - theCurrentNumBytes;
	if ( numBytesLeftInDump < BLOCK_SIZE)
	{
		theCurrentBlockSize = numBytesLeftInDump;
	}
	
	QString addressString = QString("0x") + QString::number(theCurrentDumpAddress, 16);
	QString numBytesString = QString("0x") + QString::number(theCurrentBlockSize, 16);
	
	QString dumpCmd = theDumpCommand;
	dumpCmd.replace("ADDRESS", addressString);
	dumpCmd.replace("NUMBYTES", numBytesString);
	dumpCmd.append("\n");
	
	theSerialPort->write(dumpCmd.toLatin1());
	emit serialTextReceived(dumpCmd);
	
	theCurrentState = READING_DUMP_DATA;	
}

void SerialDumper::executeReadingDumpDataState()
{
	
}

void SerialDumper::executeStartDumpCrcState()
{
	// Reset the timeout firing count to 0
	theNumTimerFiringsForOneBlock = 0;
}

void SerialDumper::executeReadingDumpCrcState()
{
	
}

void SerialDumper::executeNotDumpingState()
{
	// Close the file if it is open
	if(theOutputFile.isOpen())
	{
		qDebug() << "Closing the dump file";
		theOutputFile.close();
	}
}

QString SerialDumper::currentStateName()
{
	switch(theCurrentState)
	{
	case START_DUMP:
		return "START_DUMP";
		
	case START_DUMP_BLOCK:
		return "START_DUMP_BLOCK";
		
	case READING_DUMP_DATA:
		return "READING_DUMP_DATA";
		
	case START_DUMP_CRC:
		return "START_DUMP_CRC";
	
	case READING_DUMP_CRC:
		return "READING_DUMP_CRC";
		
	case NOT_DUMPING:
		return "NOT_DUMPING";
	}
	
	return "INVALID_STATE";
}
