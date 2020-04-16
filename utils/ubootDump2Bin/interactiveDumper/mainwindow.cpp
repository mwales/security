#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QtDebug>

#include <QMessageBox>
#include <QScrollBar>
#include <QAbstractSlider>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
    theMaxProgressValue(100),
    thePortOpen(false),
    theDumpInProgress(false)
{
	ui->setupUi(this);
	ui->theDumpButton->setEnabled(false);
	ui->theManualCommandSendButton->setEnabled(false);
	
	theBaudRateMap.insert("1200", QSerialPort::Baud1200);
	theBaudRateMap.insert("2400", QSerialPort::Baud2400);
	theBaudRateMap.insert("4800", QSerialPort::Baud4800);
	theBaudRateMap.insert("9600", QSerialPort::Baud9600);
	theBaudRateMap.insert("19200", QSerialPort::Baud19200);
	theBaudRateMap.insert("38400", QSerialPort::Baud38400);
	theBaudRateMap.insert("57600", QSerialPort::Baud57600);
	theBaudRateMap.insert("115200", QSerialPort::Baud115200);
	
	theDataBitsMap.insert("8", QSerialPort::Data8);
	theDataBitsMap.insert("7", QSerialPort::Data7);
	theDataBitsMap.insert("6", QSerialPort::Data6);
	theDataBitsMap.insert("5", QSerialPort::Data5);
	
	theFlowControlMap.insert("None", QSerialPort::NoFlowControl);
	theFlowControlMap.insert("Hardware", QSerialPort::HardwareControl);
	theFlowControlMap.insert("Software", QSerialPort::SoftwareControl);
	
	theStopBitsMap.insert("1", QSerialPort::OneStop);
	theStopBitsMap.insert("1.5", QSerialPort::OneAndHalfStop);
	theStopBitsMap.insert("2", QSerialPort::TwoStop);
	
	theParityMap.insert("None", QSerialPort::NoParity);
	theParityMap.insert("Even", QSerialPort::EvenParity);
	theParityMap.insert("Odd", QSerialPort::OddParity);
	
	connect(ui->theSerialPortButton, &QPushButton::pressed,
	        this, &MainWindow::serialButtonPressed);
	
	connect(ui->theDumpButton, &QPushButton::pressed,
	        this, &MainWindow::dumpButtonPressed);
	
	connect(ui->theManualCommandSendButton, &QPushButton::pressed,
	        this, &MainWindow::manualCmdButtonPressed);
	connect(ui->theManucalCommandLineEdit, &QLineEdit::returnPressed,
	        this, &MainWindow::manualCmdButtonPressed);
}

MainWindow::~MainWindow()
{
	delete ui;
}

void MainWindow::populateSerialPortNames(QStringList const & names)
{
	ui->theSerialPortNamesCB->insertItems(0, names);
}

void MainWindow::serialTextReceived(QString data)
{
	if (!data.isEmpty())
	{
		data[data.length()-1] = ' ';
	}
	
	ui->theSerialText->addItem(data);
	
	int numRows = ui->theSerialText->count();
		
	if(numRows >= 100)
	{
		// Take old line of text out
		ui->theSerialText->takeItem(0);
		numRows--;
	}
	
	ui->theSerialText->setCurrentRow(numRows - 1);
}

void MainWindow::updateProgress(int currentVal, int maxValue)
{
	if (maxValue != theMaxProgressValue)
	{
		theMaxProgressValue = maxValue;
		ui->theDumpProgressBar->setMaximum(maxValue);
	}
	
	ui->theDumpProgressBar->setValue(currentVal);
}



void MainWindow::serialButtonPressed()
{
	if (thePortOpen)
	{
		// Closing the serial port
		
		// Is dumping in progress?
		if (theDumpInProgress)
		{
			// User has to stop dump first!
			QMessageBox::critical(this, "Can't Close Serial Port",
			                      "Can't close serial port while dump in progress");
			return;
		}
		else
		{
			// Closing the serial port
			ui->theManualCommandSendButton->setEnabled(false);
			ui->theDumpButton->setEnabled(false);
			ui->theSerialPortButton->setText("Open");
			thePortOpen = false;
			emit closeSerialPort();
		}
	}
	else
	{
		if ( theBaudRateMap.contains(ui->theBaudRateCB->currentText()) &&
		     theDataBitsMap.contains(ui->theDataBitsCB->currentText()) &&
		     theFlowControlMap.contains(ui->theFlowControlCB->currentText()) &&
		     theStopBitsMap.contains(ui->theStopBitsCB->currentText()) &&
		     theParityMap.contains(ui->theParityCB->currentText()) )
		{
			emit openSerialPort(ui->theSerialPortNamesCB->currentText(),
			                    theBaudRateMap.value(ui->theBaudRateCB->currentText()),
			                    theDataBitsMap.value(ui->theDataBitsCB->currentText()),
			                    theFlowControlMap.value(ui->theFlowControlCB->currentText()),
			                    theStopBitsMap.value(ui->theStopBitsCB->currentText()),
			                    theParityMap.value(ui->theParityCB->currentText()) );
			
			ui->theSerialPortButton->setText("Close");
			ui->theDumpButton->setEnabled(true);
			ui->theManualCommandSendButton->setEnabled(true);
			
			thePortOpen = true;
		}
	}
}

void MainWindow::dumpButtonPressed()
{
	if (theDumpInProgress)
	{
		// Stop dumping
		theDumpInProgress = false;
		ui->theDumpButton->setText("Start Dump");
		emit abortDump();
	}
	else
	{
		// Start dumping!
		
		// Get start address
		uint64_t address;
		bool convSuccess;
		QString addressText = ui->theAddressLineEdit->text();
		if (addressText.startsWith("0x"))
		{
			// Hex
			address = addressText.toULongLong(&convSuccess, 16);
		}
		else
		{
			// Base-10
			address = addressText.toULongLong(&convSuccess, 10);			
		}
		
		if (!convSuccess)
		{
			QMessageBox::critical(this, "Invalid address", QString("Invalid address: ") + addressText);
			return;
		}
		
		uint32_t numBytes;
		QString numBytesText = ui->theNumBytesLineEdit->text();
		if (numBytesText.startsWith("0x"))
		{
			// Hex
			numBytes = numBytesText.toUInt(&convSuccess, 16);
		}
		else
		{
			// Base-10
			numBytes = numBytesText.toUInt(&convSuccess, 10);
		}
		
		if (!convSuccess)
		{
			QMessageBox::critical(this, "Invalid number of bytes", QString("Invalid num bytes: ") + numBytesText);
			return;
		}
		
		ui->theDumpButton->setText("Stop Dumping");
		theDumpInProgress = true;
		ui->theDumpProgressBar->setValue(0);
		emit startDumping(address, numBytes);
	}
}

void MainWindow::dumpingFinished()
{
	QMessageBox::information(this, "Dump Complete", "Dump complete!");
	theDumpInProgress = false;
	ui->theDumpButton->setText("Start Dump");
}

void MainWindow::portClosed()
{
	if (theDumpInProgress)
	{
		QMessageBox::critical(this, "Dump Failed", "Serial port closed while dump was in progress");
	}
	
	theDumpInProgress = false;
	thePortOpen = false;
	ui->theDumpButton->setText("Start Dump");
	ui->theDumpButton->setEnabled(false);
	ui->theManualCommandSendButton->setEnabled(false);
	ui->theSerialPortButton->setText("Open Port");
	
}

void MainWindow::manualCmdButtonPressed()
{
	emit sendManualData(ui->theManucalCommandLineEdit->text());
}

