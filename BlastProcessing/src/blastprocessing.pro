#-------------------------------------------------
#
# Project created by QtCreator 2017-05-16T23:55:13
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = blastprocessing
TEMPLATE = app


SOURCES += main.cpp\
        MainWindow.cpp \
    QemuProcessManager.cpp

HEADERS  += MainWindow.h \
    QemuProcessManager.h

FORMS    += MainWindow.ui

RESOURCES += \
    resources.qrc

CONFIG += c++11
