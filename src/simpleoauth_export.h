#ifndef SIMPLEOAUTH_EXPORT_H
#define SIMPLEOAUTH_EXPORT_H

#include <QtCore/qglobal.h>

#ifndef SIMPLEOAUTH_EXPORT
# if defined(SIMPLEOAUTH_STATIC_LIB)       // No export/import for static libraries
#  define SIMPLEOAUTH_EXPORT
# elif defined(MAKE_SIMPLEOAUTH_LIB)       // We are building this library
#  define SIMPLEOAUTH_EXPORT Q_DECL_EXPORT
# else                                     // We are using this library
#  define SIMPLEOAUTH_EXPORT Q_DECL_IMPORT
# endif
#endif

#endif // SIMPLEOAUTH_EXPORT_H
