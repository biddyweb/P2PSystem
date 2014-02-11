#-------------------------------------------------
#
# Project created by QtCreator 2014-01-21T10:27:32
#
#-------------------------------------------------

QT       += core

QT       -= gui

TARGET = PeerClientTest
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app
INCLUDEPATH     += $$PWD/..

include(../talk/talk.pri)

Debug:DESTDIR = $$PWD/../Debug
Release:DESTDIR = $$PWD/../Release

LIBS += -L$$DESTDIR -L$$DESTDIR/lib \
        -ljsoncpp



SOURCES += \
    PeerClientTest.cpp \
    transporttest.cpp \
    channeltest.cpp \
    myconductor.cpp \
    peer_connection_client.cc \
    defaults.cc


HEADERS += \
    transporttest.h \
    channeltest.h \
    myconductor.h \
    peer_connection_client.h \
    defaults.h

