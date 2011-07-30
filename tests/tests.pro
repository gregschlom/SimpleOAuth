QT       += core network testlib
TARGET = test
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app

SOURCES += \
    Test.cpp

DEFINES += SIMPLEOAUTH_STATIC_LIB

INCLUDEPATH += ../src

LIBS += -L../lib/ -lsimpleoauth
win32 {
	POST_TARGETDEPS += "../lib/simpleoauth.lib"
} else {
	POST_TARGETDEPS += "../lib/libsimpleoauth.a"
}


HEADERS += \
    Test.h
