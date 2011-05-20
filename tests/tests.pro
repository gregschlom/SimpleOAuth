QT       += core network testlib
TARGET = test
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app

SOURCES += \
    Test.cpp

DEFINES += SIMPLEOAUTH_STATIC_LIB
LIBS += -L../lib/ -lsimpleoauth
INCLUDEPATH += ../src

POST_TARGETDEPS += \
	"../lib/simpleoauth.lib" \

HEADERS += \
    Test.h
