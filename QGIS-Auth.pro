#-------------------------------------------------
#
# Project created by QtCreator 2014-09-27T15:16:53
#
#-------------------------------------------------

QT += core gui network webkit sql

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = QGIS-Auth
TEMPLATE = app

DEPENDPATH += . src
INCLUDEPATH += . src

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
    main.cpp \
    webpage.cpp \
    testwidget.cpp \
    qgsapplication.cpp \
    qgscredentials.cpp \
    qgslogger.cpp \
    qgsmessagebar.cpp \
    qgsmessagebaritem.cpp \
    qgsauthenticationmanager.cpp \
    qgsauthenticationconfig.cpp \
    qgsauthenticationcrypto.cpp \
    qgsauthenticationprovider.cpp \
    qgsauthenticationconfigwidget.cpp \
    qgsauthenticationconfigeditor.cpp \
    qgsauthenticationconfigselect.cpp \
    qgsauthenticationutils.cpp

HEADERS += \
    webpage.h \
    testwidget.h \
    qgsconfig.h \
    qgssingleton.h \
    qgsapplication.h \
    qgscredentials.h \
    qgslogger.h \
    qgsmessagebar.h \
    qgsmessagebaritem.h \
    qgsauthenticationmanager.h \
    qgsauthenticationconfig.h \
    qgsauthenticationcrypto.h \
    qgsauthenticationprovider.h \
    qgsauthenticationconfigwidget.h \
    qgsauthenticationconfigeditor.h \
    qgsauthenticationconfigselect.h \
    qgsauthenticationutils.h

FORMS += \
    webpage.ui \
    testwidget.ui \
    qgsauthenticationconfigwidget.ui \
    qgsauthenticationconfigeditor.ui \
    qgsauthenticationconfigselect.ui \
    qgsmasterpasswordresetdialog.ui

#RESOURCES += /Users/larrys/QGIS/github.com/QGIS/images/images.qrc
