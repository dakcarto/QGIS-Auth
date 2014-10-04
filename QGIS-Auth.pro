#-------------------------------------------------
#
# Project created by QtCreator 2014-09-27T15:16:53
#
#-------------------------------------------------

QT += core gui network webkit sql

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = QGIS-Auth
TEMPLATE = app
mac {
    QMAKE_MACOSX_DEPLOYMENT_TARGET = 10.7
}

DEPENDPATH += . src
INCLUDEPATH += . src
INCLUDEPATH += $(HOMEBREW_PREFIX)/include

QMAKE_CXXFLAGS += -isystem $(HOMEBREW_PREFIX)/include

LIBS += -L$(HOMEBREW_PREFIX)/lib -lcryptopp
#LIBS += $(HOMEBREW_PREFIX)/lib/libcryptopp.a

# just for Mac, Homebrew shared lib build has CRYPTOPP_DISABLE_ASM defined
# build here has to define the same, or linking errors about missing vtables
DEFINES += CRYPTOPP_DISABLE_ASM

SOURCES += \
    main.cpp \
    webpage.cpp \
    testwidget.cpp \
    qgsauthenticationmanager.cpp \
    qgsapplication.cpp \
    qgsauthenticationconfig.cpp \
    qgscredentials.cpp \
    qgsauthenticationcrypto.cpp \
    qgsauthenticationprovider.cpp \
    qgsauthenticationconfigwidget.cpp \
    qgsauthenticationconfigeditor.cpp \
    qgsauthenticationconfigselect.cpp

HEADERS += \
    webpage.h \
    testwidget.h \
    qgsauthenticationmanager.h \
    qgsapplication.h \
    qgsauthenticationconfig.h \
    qgscredentials.h \
    qgsauthenticationcrypto.h \
    qgsauthenticationprovider.h \
    qgsauthenticationconfigwidget.h \
    qgsauthenticationconfigeditor.h \
    qgsauthenticationconfigselect.h

#RESOURCES += qgis-auth.qrc
FORMS += \
    webpage.ui \
    testwidget.ui \
    qgsauthenticationconfigwidget.ui \
    qgsauthenticationconfigeditor.ui \
    qgsauthenticationconfigselect.ui
