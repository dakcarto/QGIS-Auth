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
INCLUDEPATH += /usr/local/include
#LIBS += -L/usr/local/lib -lcryptopp
LIBS += /usr/local/lib/libcryptopp.a

SOURCES += main.cpp\
        mainwindow.cpp \
    qgsauthenticationselectorbase.cpp \
    qgsauthenticationmanager.cpp \
    qgsapplication.cpp

HEADERS  += mainwindow.h \
    qgsauthenticationselectorbase.h \
    qgsauthenticationmanager.h \
    qgsapplication.h

#RESOURCES += qgis-auth.qrc
FORMS    += mainwindow.ui \
    qgsauthenticationselectorbase.ui
