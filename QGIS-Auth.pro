#-------------------------------------------------
#
# Project created by QtCreator 2014-09-27T15:16:53
#
#-------------------------------------------------

QT       += core gui network sql

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

SOURCES += main.cpp\
  mainwindow.cpp \
  qgsauthenticationselectorbase.cpp \
  qgsauthenticationmanager.cpp \
  qgsapplication.cpp \
  qgsauthenticationconfig.cpp \
  qgscredentials.cpp \
  qgsauthenticationcrypto.cpp \
  qgsauthenticationprovider.cpp

HEADERS += mainwindow.h \
  qgsauthenticationselectorbase.h \
  qgsauthenticationmanager.h \
  qgsapplication.h \
  qgsauthenticationconfig.h \
  qgscredentials.h \
  qgsauthenticationcrypto.h \
  qgsauthenticationprovider.h

#RESOURCES += qgis-auth.qrc
FORMS += mainwindow.ui \
  qgsauthenticationselectorbase.ui
