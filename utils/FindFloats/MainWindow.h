#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include <QMap>
#include <QStringList>
#include "DecodedValue.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
   Q_OBJECT

public:
   explicit MainWindow(QWidget *parent = nullptr);
   ~MainWindow();

protected slots:

   void clearUserData();

   void convertUserData();

   void displayData();

private:
   QString prettify(QByteArray data);

   QByteArray reverseArray(QByteArray const & data);

   void findXByteValue(int numBytes, QByteArray const & data);

   void decode1ByteInteger(QByteArray const & data, int offset);

   void decode2ByteInteger(QByteArray const & data, int offset);

   void decode4ByteInteger(QByteArray const & data, int offset);

   void decode8ByteInteger(QByteArray const & data, int offset);

   void decode4ByteFloat(QByteArray const & data, int offset);
   void decode8ByteDouble(QByteArray const & data, int offset);

   Ui::MainWindow *ui;

   QByteArray theUserHex;

   QMap<DecodedValue, QStringList> theValues;

};

#endif // MAINWINDOW_H
