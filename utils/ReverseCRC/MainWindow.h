#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include <QMap>
#include <QStringList>

#include <iostream>


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

   void displayData(int startByte, int endByte, std::string crcType, std::string const & seedVal);

   void crcSearch();

private:

   QString prettify(QByteArray data);





   Ui::MainWindow *ui;

   QByteArray theUserHex;



};

#endif // MAINWINDOW_H
