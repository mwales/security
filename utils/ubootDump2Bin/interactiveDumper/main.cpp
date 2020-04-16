#include "mainwindow.h"
#include <QApplication>
#include "SerialDumper.h"

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	MainWindow w;
	SerialDumper sd;
	
	sd.initMainWindow(&w);
	
	w.show();
	
	return a.exec();
}
