#include "MainWindow.h"
#include "ui_MainWindow.h"

#include <QMessageBox>
#include <QtDebug>
#include <stdint.h>

#include "CrcTool.h"

MainWindow::MainWindow(QWidget *parent) :
   QMainWindow(parent),
   ui(new Ui::MainWindow)
{
   ui->setupUi(this);

   connect(ui->theClearButton, &QPushButton::pressed,
           this, &MainWindow::clearUserData);

   connect(ui->theConvertButton, &QPushButton::pressed,
           this, &MainWindow::convertUserData);

}

MainWindow::~MainWindow()
{
   delete ui;
}

void MainWindow::clearUserData()
{
   ui->theUserData->clear();
}

void MainWindow::convertUserData()
{
   ui->theSimplifiedHex->clear();
   ui->theResults->clearContents();
   ui->theResults->setRowCount(0);

   QString userData = ui->theUserData->text().toUpper();

   QString filteredData;
   foreach(QChar singleChar, userData)
   {
      if ( (singleChar >= '0') && (singleChar <= '9'))
      {
         filteredData += singleChar;
         continue;
      }

      if ( (singleChar >= 'A') && (singleChar <= 'F'))
      {
         filteredData += singleChar;
         continue;
      }
   }

   // Make sure user gave us an even number of hex characters
   if ( (filteredData.length() % 2) == 1)
   {
      QMessageBox::critical(this, "Error", "Odd number of hexadecimal digits");

      return;
   }

   QByteArray dataArray;
   while(filteredData.length())
   {
      QString currentByteHexString;
      currentByteHexString = filteredData.left(2);
      bool status;
      unsigned int currentByte = currentByteHexString.toUInt(&status, 16);

      if (!status)
      {
         QMessageBox::critical(this, "Error encoding",
                               "Couldn't convert " + currentByteHexString + " to an integer");
         return;
      }

      dataArray.append( (char) (currentByte & 0xff) );

      filteredData.remove(0,2);
   }

   // Display the prettied up version of the hex
   ui->theSimplifiedHex->setText(prettify(dataArray));

   theUserHex = dataArray;

   crcSearch();
}

void MainWindow::crcSearch()
{
   // CRC-8 Search
   for(int startByte = 0; startByte < theUserHex.length() - 2; startByte++)
   {
      for(int curLength = theUserHex.length() - startByte - 1; curLength >= 0; curLength--)
      {
         uint8_t crcFromData = static_cast<uint8_t>(theUserHex.at(curLength));
         uint8_t* bufferStart = reinterpret_cast<uint8_t*>(theUserHex.data()) + startByte;

         std::vector<uint8_t> seedList = CrcTool::calculateCrc8Seed(bufferStart,
                                                                    curLength,
                                                                    crcFromData);

         for(std::vector<uint8_t>::iterator it = seedList.begin();
             it != seedList.end(); it++)
         {
            char tempBuffer[80];
            sprintf(tempBuffer, "0x%02x", *it);

            displayData(startByte, curLength, "CRC-8", tempBuffer);
         }
      }
   }

   // CRC-16 Search
   for(int startByte = 0; startByte < theUserHex.length() - 3; startByte++)
   {
      for(int curLength = theUserHex.length() - startByte - 2; curLength >= 0; curLength--)
      {
         uint16_t crcFromDataHigh = static_cast<uint16_t>(theUserHex.at(curLength)) & 0x00ff;
         uint16_t crcFromDataLow = static_cast <uint16_t>(theUserHex.at(curLength +1)) & 0x00ff;
         uint16_t crcFromDataBE = (crcFromDataHigh << 8) + (crcFromDataLow);
         uint16_t crcFromDataLE = (crcFromDataLow << 8) + (crcFromDataHigh);


         uint8_t* bufferStart = reinterpret_cast<uint8_t*>(theUserHex.data()) + startByte;

         std::vector<uint16_t> seedListBE = CrcTool::calculateCrc16Seed(bufferStart,
                                                                      curLength,
                                                                      crcFromDataBE);
         std::vector<uint16_t> seedListLE = CrcTool::calculateCrc16Seed(bufferStart,
                                                                      curLength,
                                                                      crcFromDataLE);

         for(std::vector<uint16_t>::iterator it = seedListBE.begin();
             it != seedListBE.end(); it++)
         {
            char tempBuffer[80];
            sprintf(tempBuffer, "0x%04x", *it);

            displayData(startByte, curLength, "CRC-16 BE", tempBuffer);
         }

         for(std::vector<uint16_t>::iterator it = seedListLE.begin();
             it != seedListLE.end(); it++)
         {
            char tempBuffer[80];
            sprintf(tempBuffer, "0x%04x", *it);

            displayData(startByte, curLength, "CRC-16 LE", tempBuffer);
         }
      }
   }
}

void MainWindow::displayData(int startByte, int len, std::string crcType, std::string const &  seedVal)
{
   int rowNum = ui->theResults->rowCount();
   ui->theResults->setRowCount(rowNum + 1);

   ui->theResults->setItem(rowNum, 0, new QTableWidgetItem(QString::number(startByte)));
   ui->theResults->setItem(rowNum, 1, new QTableWidgetItem(QString::number(len)));
   ui->theResults->setItem(rowNum, 2, new QTableWidgetItem(QString(crcType.c_str())));
   ui->theResults->setItem(rowNum, 3, new QTableWidgetItem(QString(seedVal.c_str())));
}


QString MainWindow::prettify(QByteArray data)
{
   QString retVal;

   QByteArray first8, second8;
   for(int i = 0; i < data.length(); i += 16)
   {
      first8.clear();
      second8.clear();

      if (i + 8 < data.length() - 1)
      {

         first8 = data.mid(i, 8);

         if ((i + 16) < data.length() - 1)
         {
            second8 = data.mid(i + 8, 8);
         }
         else
         {
            second8 = data.mid(i + 8);
         }
      }
      else
      {
         first8 = data.mid(i);
      }

      retVal += first8.toHex(' ');
      retVal += "  ";
      retVal += second8.toHex(' ');
      retVal += "\n";
   }

   return retVal;
}

