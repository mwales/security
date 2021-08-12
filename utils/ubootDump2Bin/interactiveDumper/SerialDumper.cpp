#include "SerialDumper.h"
#include <QSerialPortInfo>
#include <QList>
#include <QMessageBox>
#include <QtDebug>
#include "mainwindow.h"
#include "crc32.h"

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
    theNumTimerFiringsForOneBlock(0),
    theReceivedCrc(0),
    theCrcReceived(false)
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
	
	if (!connect(this, &SerialDumper::updateProgress,
	             mw, &MainWindow::updateProgress))
	{
		qWarning() << "Connection for stopDump function failed in" << __PRETTY_FUNCTION__;
	}
	
	if (!connect(this, &SerialDumper::dumpComplete,
	             mw, &MainWindow::dumpFinished))
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
                             QString crcCmd, QString command)
{
	qDebug() << "startDump(0x" << QString::number(address, 16) << ", numBytes=0x"
	         << QString::number(numBytes, 16) << ", filename=" << filename
		 << ", crcCmd=" << crcCmd << ", cmd=" << command << ")";

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
	theCrcCommand = crcCmd;
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
	
	theCurrentState = STOP_DUMPING;
	theDumpFinishMsg = "Dump stopped early due to user input";
	executeState();
}

void SerialDumper::sendSerialData(QString data)
{
	if (data.at(data.size() - 1) != '\n')
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
		bool endWithNewLine = text.at(text.size() - 1) == '\n';
		
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

void SerialDumper::serialError(QSerialPort::SerialPortError err)
{
	qDebug() << "Serial Port Error: " << serialPortErrorToString(err);
	
	theCurrentState = STOP_DUMPING;
	theDumpFinishMsg = "Dump stopped due to serial error: " + serialPortErrorToString(err);
	executeState();
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

void SerialDumper::processSingleLineDumpData(QString dumpData)
{
	dumpData = dumpData.trimmed();
	
	QStringList tokens = dumpData.split(QRegExp("[: ]+"));
	// qDebug() << "Token List: " << tokens;
	
	// There needs to be 18 tokens: address, 16 bytes, ascii
	// ascii could be all spaces, not a token, so only 17
	if (tokens.length() < 17)
	{
		// qDebug() << "  process failed, not enough tokens (" << tokens.length() << ")";
		return;
	}
	
	// Make sure the first 17 tokens are the correct length:  address and 16 bytes
	if (tokens.at(0).length() != 8)
	{
		// qDebug() << "  addresss token the wrong size [" << tokens.at(0) << "], with len="
		//          << tokens.at(0).length();
		return;
	}
	
	for(int i = 1; i <= 16; i++)
	{
		if (tokens.at(i).length() != 2)
		{
			// qDebug() << "  process failed, data token " << i << " wrong size";
			// qDebug() << " token [" << tokens.at(i) << "], with len="
			//          << tokens.at(i).length();
			return;
		}
	}
	
	// All the first 17 tokens must be hex
	for(int i = 0; i < 17; i++)
	{
		if (!isHexString(tokens.at(i)))
		{
			// qDebug() << "  process failed, data token text not hex";
			return;
		}
	}
	
	unsigned long temp[17];
	for(int i = 0; i < 17; i++)
	{
		temp[i] = tokens.at(i).toULong(nullptr, 16);
	}
	
	for(int i = 1; i <= 16; i++)
	{
		theCurrentDumpBlock.append( static_cast<char>(temp[i] & 0xff) );
	}
	
	// qDebug() << "  Added 0x10 bytes of data to current block";
}

/**
 * Format of CRC reply
 * CRC32 for 20000000 ... 20000fff ==> aabbccdd
 */
void SerialDumper::processSingleLineCrcData(QString data)
{
	data = data.trimmed();
	
	qDebug() << __PRETTY_FUNCTION__ << " called with: " << data;
	
	QStringList tokens = data.split(QRegExp("[: \\.=>]+"));
	// qDebug() << "Token List: " << tokens;
	
	// Tokens should be "CRC32", "for", startAddr, endAddr, crc32Val
	
	// Validate the number of tokens
	if (tokens.size() != 5)
	{
		qDebug() << "Invalid number of tokens, expected 5:" << tokens;
		return;
	}
	
	// Validate the first two tokens
	if ( (tokens[0] != "CRC32") || (tokens[1] != "for") )
	{
		qDebug() << "One of the first 2 tokens invalid:" << tokens[0] << "or" << tokens[1];
		return;
	}
	
	bool success = false;
	uint32_t crcVal = tokens[4].toUInt(&success, 16);
	
	if (!success)
	{
		qDebug() << "CRC token didn't convert to hex:" << tokens[4];
		return;
	}
	
	theReceivedCrc = crcVal;
	theCrcReceived = true;
}

void SerialDumper::processSingleLine(QByteArray data)
{
	// qDebug() << "Going to process a line of " << data.length() << "bytes";
	
	if (!theOldData.isEmpty())
	{
		data = theOldData.append(data);
	}
	
	if (data.at(data.size() - 1) == '\n')
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
	
	if (theCurrentState == READING_DUMP_DATA)
	{
		processSingleLineDumpData(QString(data));
	}
	else if (theCurrentState == READING_DUMP_CRC)
	{
		processSingleLineCrcData(QString(data));
	}
	else
	{
		qDebug() << "  Not processing serial data in state" << currentStateName();
	}
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
		
	case STOP_DUMPING:
		executeStopDumpingState();
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
	uint64_t numBytesLeftInDump = theFinalDumpSize - theCurrentNumBytes;

	qDebug() << "StartDumpBlockState.  numBytesLeft = " << numBytesLeftInDump << ", curBlkSize = "
	         << theCurrentBlockSize;

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
	if (theCurrentDumpBlock.size() == BLOCK_SIZE)
	{
		// We received the full block!  Now verify the data!
		theCurrentState = START_DUMP_CRC;
		executeState();
	}
	else
	{
		qDebug() << "Have " << theCurrentDumpBlock.size() << "bytes of data of block size"
		         << BLOCK_SIZE;
	}
}

void SerialDumper::finishedDumpingBlock()
{
	theOutputFile.write(theCurrentDumpBlock);
	theCurrentDumpAddress += theCurrentDumpBlock.size();
	theCurrentNumBytes += theCurrentDumpBlock.size();
			
	emit updateProgress(theCurrentNumBytes, theFinalDumpSize);
		
	theCurrentDumpBlock.clear();

	if (theCurrentNumBytes >= theFinalDumpSize)
	{
		// We are done dumping!
				
		emit updateProgress(theCurrentNumBytes, theFinalDumpSize);
				
		theDumpFinishMsg = QString("Dumped 0x%1 bytes successfully!").arg(QString::number(theCurrentNumBytes, 16));
		theCurrentState = STOP_DUMPING;
	}
	else
	{
		// Goto next block for dumping
		theCurrentState = START_DUMP_BLOCK;
	}
			
	executeState();
}

void SerialDumper::executeStartDumpCrcState()
{
	// If CRC field is empty, skip CRC checking (may not be installed)
	if (theCrcCommand.isEmpty())
	{
		finishedDumpingBlock();
		return;
	}

	// Reset the timeout firing count to 0
	theNumTimerFiringsForOneBlock = 0;
	
	QString addressString = QString("0x") + QString::number(theCurrentDumpAddress, 16);
	QString numBytesString = QString("0x") + QString::number(theCurrentBlockSize, 16);
	
	// Format for crc32 command
	// crc32 0xaabbccdd 0xaabb
	// crc32 address length
	QString crcCommand = theCrcCommand;
	crcCommand.replace("ADDRESS", addressString);
	crcCommand.replace("NUMBYTES", numBytesString);
	crcCommand.append("\n");
	
	theSerialPort->write(crcCommand.toLatin1());
	emit serialTextReceived(crcCommand);
	
	theCurrentState = READING_DUMP_CRC;
	theReceivedCrc = 0;
	theCrcReceived = false;
}

void SerialDumper::executeReadingDumpCrcState()
{
	if (theCrcReceived)
	{
		if (validateCrcValue())
		{
			// CRC checks out, move to next block
			finishedDumpingBlock();
	}
		else
		{
			// Redump this block
			theReceivedCrc = 0;
			theCrcReceived = false;
			theCurrentState = START_DUMP_BLOCK;
			executeState();
		}
	}
}

void SerialDumper::executeStopDumpingState()
{
	// If there is a partial block of data, just write it to file anyways
	if (!theCurrentDumpBlock.isEmpty())
	{
		theOutputFile.write(theCurrentDumpBlock);
		theCurrentDumpAddress += theCurrentDumpBlock.size();
		theCurrentNumBytes += theCurrentDumpBlock.size();
		theCurrentDumpBlock.clear();
	}
	
	// One last progress update
	emit updateProgress(theCurrentNumBytes, theFinalDumpSize);
	emit dumpComplete(theDumpFinishMsg);
		
	qDebug() << "Closing the dump file";
	theOutputFile.close();
	
	theCurrentState = NOT_DUMPING;
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
		
	case STOP_DUMPING:
		return "STOP_DUMPING";
		
	case NOT_DUMPING:
		return "NOT_DUMPING";
	}
	
	return "INVALID_STATE";
}

QString SerialDumper::serialPortErrorToString(QSerialPort::SerialPortError err)
{
	switch(err)
	{
	case QSerialPort::NoError:
		return "No Error";
	case QSerialPort::DeviceNotFoundError:
		return "DeviceNotFoundError";
	case QSerialPort::PermissionError:
		return "Permission Error";
	case QSerialPort::OpenError:
		return "OpenError";
	case QSerialPort::NotOpenError:
		return "Not Open Error";
	case QSerialPort::ParityError:
		return "Parity Error";
	case QSerialPort::FramingError:
		return "Framing Error";
	case QSerialPort::BreakConditionError:
		return "Break Condition Error";
	case QSerialPort::WriteError:
		return "Write Error";
	case QSerialPort::ReadError:
		return "Read Error";
	case QSerialPort::ResourceError:
		return "Resource Error";
	case QSerialPort::UnsupportedOperationError:
		return "Unsupported Operation Error";
	case QSerialPort::TimeoutError:
		return "Timeout Error";
	case QSerialPort::UnknownError:
		return "Unknown Error";		
	}
	
	return "Unnkown Error Code";
}

bool SerialDumper::validateCrcValue()
{
	// qDebug() << "validate CRC " << QString::number(theReceivedCrc, 16);
	
	uint32_t ourChecksum = crc32buf(theCurrentDumpBlock.data(), theCurrentDumpBlock.size());
	
	// qDebug() << "calculated CRC " << QString::number(ourChecksum, 16);
	
	return theReceivedCrc == ourChecksum;
}
