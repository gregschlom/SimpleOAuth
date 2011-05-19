TEMPLATE = lib
CONFIG   += static create_prl
QT       += network
TARGET   = simpleoauth
DESTDIR  = $$OUT_PWD/../lib
VERSION = 0.1

CONFIG(static) {
	DEFINES += SIMPLEOAUTH_STATIC_LIB
} else {
	DEFINES += MAKE_SIMPLEOAUTH_LIB
}

SOURCES += \
	oauth_token.cpp \
	oauth_helper.cpp

PRIVATE_HEADERS += \
	oauth_token_p.h

PUBLIC_HEADERS  += \
	simpleoauth_export.h \
	oauth_token.h \
	oauth_helper.h

HEADERS += $$PRIVATE_HEADERS $$PUBLIC_HEADERS

headers.files = $$PUBLIC_HEADERS
headers.path = $$OUT_PWD/../include/simpleoauth
INSTALLS += headers