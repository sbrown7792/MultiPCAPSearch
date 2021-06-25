QT       += core gui concurrent

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = MultiPCAPSearch
TEMPLATE = app

DEFINES += QT_DEPRECATED_WARNINGS

SOURCES += \
    Source/pcap.cpp \
    Source/main.cpp \
    Source/mainwindow.cpp

HEADERS += \
    Source/pcap.h \
    Source/mainwindow.h

FORMS += \
    Source\mainwindow.ui


