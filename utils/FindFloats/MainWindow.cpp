#include "MainWindow.h"
#include "ui_MainWindow.h"

#include <QMessageBox>
#include <QtDebug>
#include <stdint.h>


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

   ui->theSimplifiedHex->setText(prettify(dataArray));

   theValues.clear();

   findXByteValue(1, dataArray);
   findXByteValue(2, dataArray);
   findXByteValue(4, dataArray);
   findXByteValue(8, dataArray);

   displayData();
}

void MainWindow::displayData()
{
   ui->theResults->clear();

   int row = 0;
   int col = 0;
   foreach(DecodedValue dv, theValues.keys())
   {
      QStringList rowData = theValues.value(dv);

      if (!row)
      {
         // Size the table correctly
         ui->theResults->setColumnCount(rowData.length());
         ui->theResults->setRowCount(theValues.keys().length());
      }

      col = 0;
      foreach(QString cellString, rowData)
      {
         ui->theResults->setItem(row, col, new QTableWidgetItem(cellString));
         col++;
      }

      row++;
   }
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

QByteArray MainWindow::reverseArray(QByteArray const & data)
{
   QByteArray retVal;
   for(auto  it = data.rbegin(); it != data.rend(); it++)
   {
      retVal.append(*it);
   }

   return retVal;
}

void MainWindow::findXByteValue(int numBytes, QByteArray const & data)
{
    for(int i = 0; i <= data.length() - numBytes; i++)
    {
       QByteArray dataChunk = data.mid(i, numBytes);
       QByteArray reverseChunk = reverseArray(dataChunk);

       switch(numBytes)
       {
       case 1:
          decode2ByteInteger(dataChunk, i);
          break;

       case 2:
          decode2ByteInteger(dataChunk, i);
          decode2ByteInteger(reverseChunk, i);
          break;

       case 4:
          decode4ByteInteger(dataChunk, i);
          decode4ByteInteger(reverseChunk, i);

          decode4ByteFloat(dataChunk, i);
          decode4ByteFloat(reverseChunk, i);
          break;

       case 8:
          decode8ByteInteger(dataChunk, i);
          decode8ByteInteger(reverseChunk, i);

          decode8ByteDouble(dataChunk, i);
          decode8ByteDouble(reverseChunk, i);
          break;
       }
    }
}

void MainWindow::decode1ByteInteger(QByteArray const & data, int offsetVal)
{
   int8_t sValue;
   memcpy(&sValue, data.data(), 1);
   DecodedValue sVal( (double) sValue, offsetVal, data, "int8_t");
   theValues.insert(sVal, sVal.getTableData());

   uint8_t uValue;
   memcpy(&uValue, data.data(), 1);
   DecodedValue uVal( (double) uValue, offsetVal, data, "uint8_t");
   theValues.insert(uVal, uVal.getTableData());
}

void MainWindow::decode2ByteInteger(QByteArray const & data, int offsetVal)
{
   int16_t sValue;
   memcpy(&sValue, data.data(), 2);
   DecodedValue sVal( (double) sValue, offsetVal, data, "int16_t");
   theValues.insert(sVal, sVal.getTableData());

   uint16_t uValue;
   memcpy(&uValue, data.data(), 2);
   DecodedValue uVal( (double) uValue, offsetVal, data, "uint16_t");
   theValues.insert(uVal, uVal.getTableData());
}

void MainWindow::decode4ByteInteger(QByteArray const & data, int offsetVal)
{
   int32_t sValue;
   memcpy(&sValue, data.data(), 4);
   DecodedValue sVal( (double) sValue, offsetVal, data, "int32_t");
   theValues.insert(sVal, sVal.getTableData());

   uint32_t uValue;
   memcpy(&uValue, data.data(), 4);
   DecodedValue uVal( (double) uValue, offsetVal, data, "uint32_t");
   theValues.insert(uVal, uVal.getTableData());
}

void MainWindow::decode8ByteInteger(QByteArray const & data, int offsetVal)
{
   int64_t sValue;
   memcpy(&sValue, data.data(), 8);
   DecodedValue sVal( (double) sValue, offsetVal, data, "int64_t");
   theValues.insert(sVal, sVal.getTableData());

   uint64_t uValue;
   memcpy(&uValue, data.data(), 8);
   DecodedValue uVal( (double) uValue, offsetVal, data, "uint64_t");
   theValues.insert(uVal, uVal.getTableData());
}

void MainWindow::decode4ByteFloat(QByteArray const & data, int offset)
{
   float fValue;
   memcpy(&fValue, data.data(), 4);
   DecodedValue sVal( fValue, offset, data, "float");
   theValues.insert(sVal, sVal.getTableData());
}

void MainWindow::decode8ByteDouble(QByteArray const & data, int offset)
{
   double fValue;
   memcpy(&fValue, data.data(), 8);
   DecodedValue sVal( fValue, offset, data, "double");
   theValues.insert(sVal, sVal.getTableData());
}
