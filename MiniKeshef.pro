#-------------------------------------------------
#
# Project created by QtCreator 2018-01-04T14:09:14
#
#-------------------------------------------------

QT       += core

QT       -= gui

TARGET = MiniKeshef
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app


SOURCES += main.cpp \
    libpcapsniffer.cpp \
    Ethernet.cpp \
    Ip.cpp \
    Icmp.cpp \
    Arp.cpp

LIBS += -lpcap

HEADERS += \
    libpcapsniffer.h \
    Ethernet.h \
    Ip.h \
    Icmp.h \
    Arp.h
