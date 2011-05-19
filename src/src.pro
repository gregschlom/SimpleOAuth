TEMPLATE = lib
CONFIG   += static create_prl
QT       += network
TARGET   = simpleoauth
DESTDIR  = $$lib
VERSION = 0.1

CONFIG(static) {
	DEFINES += SIMPLEOAUTH_STATIC_LIB
} else {
	DEFINES += MAKE_SIMPLEOAUTH_LIB
}

SOURCES += \
	oauth_token.cpp \
	oauth_helper.cpp

HEADERS  += \
	simpleoauth_export.h \
	oauth_token_p.h \
	oauth_token.h \
	oauth_helper.h
