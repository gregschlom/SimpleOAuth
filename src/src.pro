TEMPLATE = lib
CONFIG   += static
QT       += network
TARGET   = simpleoauth
DESTDIR  = $$lib
CONFIG += create_prl

VERSION = 0.1

SOURCES += \
	oauth_token.cpp \
	oauth_helper.cpp

HEADERS  += \
	oauth_token_p.h \
	oauth_token.h \
	oauth_helper.h
