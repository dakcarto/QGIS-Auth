#-------------------------------------------------
#
# Project created by QtCreator 2014-09-27T15:16:53
#
#-------------------------------------------------

QT += core gui network webkit sql

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = QGIS-Auth
TEMPLATE = app

DEPENDPATH += . src src/app src/core src/gui src/core/security src/gui/security
INCLUDEPATH += . src src/app src/core src/gui src/core/security src/gui/security

DEFINES += CORE_EXPORT=""
DEFINES += GUI_EXPORT=""
DEFINES += QGISDEBUG

win32 {
    INCLUDEPATH += $(OSGEO4W_ROOT)/include
    #LIBS += -L$(OSGEO4W_ROOT)/lib -lqca
    CONFIG += crypto
}
mac {
    QMAKE_MACOSX_DEPLOYMENT_TARGET = 10.7
    INCLUDEPATH += $(HOMEBREW_PREFIX)/include
    INCLUDEPATH += $(HOMEBREW_PREFIX)/opt/qca/lib/qca.framework/Headers
    LIBS += -F$(HOMEBREW_PREFIX)/opt/qca/lib -framework qca
    QMAKE_CXXFLAGS += -isystem $(HOMEBREW_PREFIX)/include
    QMAKE_CFLAGS += -Wno-error=format-security
}

CONFIG += debug

SOURCES += \
    src/app/main.cpp \
    src/app/webpage.cpp \
    src/app/testwidget.cpp \
    src/core/qgsapplication.cpp \
    src/core/qgscredentials.cpp \
    src/core/qgslogger.cpp \
    src/gui/qgsmessagebar.cpp \
    src/gui/qgsmessagebaritem.cpp \
    src/core/security/qgsauthenticationmanager.cpp \
    src/core/security/qgsauthenticationconfig.cpp \
    src/core/security/qgsauthenticationcrypto.cpp \
    src/core/security/qgsauthenticationprovider.cpp \
    src/gui/security/qgsauthenticationconfigwidget.cpp \
    src/gui/security/qgsauthenticationconfigeditor.cpp \
    src/gui/security/qgsauthenticationconfigselect.cpp \
    src/gui/security/qgsauthenticationutils.cpp

HEADERS += \
    src/app/webpage.h \
    src/app/testwidget.h \
    src/qgsconfig.h \
    src/core/qgssingleton.h \
    src/core/qgsapplication.h \
    src/core/qgscredentials.h \
    src/core/qgslogger.h \
    src/gui/qgsmessagebar.h \
    src/gui/qgsmessagebaritem.h \
    src/core/security/qgsauthenticationmanager.h \
    src/core/security/qgsauthenticationconfig.h \
    src/core/security/qgsauthenticationcrypto.h \
    src/core/security/qgsauthenticationprovider.h \
    src/gui/security/qgsauthenticationconfigwidget.h \
    src/gui/security/qgsauthenticationconfigeditor.h \
    src/gui/security/qgsauthenticationconfigselect.h \
    src/gui/security/qgsauthenticationutils.h

FORMS += \
    src/ui/webpage.ui \
    src/ui/testwidget.ui \
    src/ui/qgsmasterpasswordresetdialog.ui \
    src/ui/qgsauthenticationconfigwidget.ui \
    src/ui/qgsauthenticationconfigeditor.ui \
    src/ui/qgsauthenticationconfigselect.ui

RESOURCES += images/images.qrc
