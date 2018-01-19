#-------------------------------------------------
#
# Project created by QtCreator 2017-05-16T23:55:13
#
#-------------------------------------------------

QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = qemuconfigtool
TEMPLATE = app


SOURCES += main.cpp\
        MainWindow.cpp \
    QemuProcessManager.cpp \
    SocketCommandInterface.cpp \
    QmpSocketMgr.cpp \
    JumboMessageBox.cpp \
    QemuConfiguration.cpp \
    BlastProcessing.cpp \
    BPRunner.cpp

HEADERS  += MainWindow.h \
    QemuProcessManager.h \
    SocketCommandInterface.h \
    QmpSocketMgr.h \
    JumboMessageBox.h \
    QemuConfiguration.h \
    BlastProcessing.h \
    BPRunner.h

FORMS    += MainWindow.ui \
    JumboMessageBox.ui \
    BlastProcessing.ui

RESOURCES += \
    resources.qrc

CONFIG += c++11

# Debug Defines
DEFINES += QEMU_MGR_DEBUG
DEFINES += MAIN_WIN_DEBUG
DEFINES += SOCK_CMD_DEBUG
DEFINES += QMP_SOCK_DEBUG
DEFINES += BLAST_PROCESSING_DEBUG
