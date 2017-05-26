#-------------------------------------------------
#
# Project created by QtCreator 2017-05-16T23:55:13
#
#-------------------------------------------------

QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = blastprocessing
TEMPLATE = app


SOURCES += main.cpp\
        MainWindow.cpp \
    QemuProcessManager.cpp \
    SocketCommandInterface.cpp \
    QmpSocketMgr.cpp

HEADERS  += MainWindow.h \
    QemuProcessManager.h \
    SocketCommandInterface.h \
    QmpSocketMgr.h

FORMS    += MainWindow.ui

RESOURCES += \
    resources.qrc

CONFIG += c++11
