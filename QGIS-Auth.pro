#-------------------------------------------------
#
# Project created by QtCreator 2014-09-27T15:16:53
#
#-------------------------------------------------

QT += core gui network webkit sql

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = QGIS-Auth
TEMPLATE = app

DEPENDPATH += . src src/app src/core src/gui src/core/auth src/gui/auth
INCLUDEPATH += . src src/app src/core src/gui src/core/auth src/gui/auth

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
    src/core/qgis.cpp \
    src/core/qgsapplication.cpp \
    src/core/qgscredentials.cpp \
    src/core/qgslogger.cpp \
    src/core/qgsmessagelog.cpp \
    src/core/qgsnetworkaccessmanager.cpp \
    src/gui/qgscollapsiblegroupbox.cpp \
    src/gui/qgsfilterlineedit.cpp \
    src/gui/qgsmessagebar.cpp \
    src/gui/qgsmessagebaritem.cpp \
    src/core/auth/qgsauthenticationmanager.cpp \
    src/core/auth/qgsauthenticationconfig.cpp \
    src/core/auth/qgsauthenticationcrypto.cpp \
    src/core/auth/qgsauthenticationprovider.cpp \
    src/gui/auth/qgsauthenticationconfigwidget.cpp \
    src/gui/auth/qgsauthenticationconfigeditor.cpp \
    src/gui/auth/qgsauthenticationconfigselect.cpp \
    src/gui/auth/qgsauthenticationidentitieseditor.cpp \
    src/gui/auth/qgsauthenticationserverseditor.cpp \
    src/gui/auth/qgsauthenticationauthoritieseditor.cpp \
    src/gui/auth/qgsauthenticationutils.cpp \
    src/gui/auth/qgsauthenticationcertificateinfo.cpp \
    src/gui/auth/qgsauthenticationimportcertdialog.cpp \
    src/core/auth/qgsauthenticationcertutils.cpp \
    src/gui/auth/qgsauthenticationcerttrustpolicycombobox.cpp \
    src/gui/auth/qgsauthenticationtrustedcasdialog.cpp \
    src/gui/auth/qgsauthenticationimportidentitydialog.cpp \
    src/gui/auth/qgsauthenticationsslconfigwidget.cpp \
    src/gui/auth/qgsauthenticationsslimportdialog.cpp

HEADERS += \
    src/app/webpage.h \
    src/app/testwidget.h \
    src/qgsconfig.h \
    src/qgsversion.h \
    src/core/qgis.h \
    src/core/qgssingleton.h \
    src/core/qgsapplication.h \
    src/core/qgscredentials.h \
    src/core/qgslogger.h \
    src/core/qgsmessagelog.h \
    src/core/qgsnetworkaccessmanager.h \
    src/gui/qgscollapsiblegroupbox.h \
    src/gui/qgsfilterlineedit.h \
    src/gui/qgsmessagebar.h \
    src/gui/qgsmessagebaritem.h \
    src/core/auth/qgsauthenticationmanager.h \
    src/core/auth/qgsauthenticationconfig.h \
    src/core/auth/qgsauthenticationcrypto.h \
    src/core/auth/qgsauthenticationprovider.h \
    src/gui/auth/qgsauthenticationconfigwidget.h \
    src/gui/auth/qgsauthenticationconfigeditor.h \
    src/gui/auth/qgsauthenticationconfigselect.h \
    src/gui/auth/qgsauthenticationidentitieseditor.h \
    src/gui/auth/qgsauthenticationserverseditor.h \
    src/gui/auth/qgsauthenticationauthoritieseditor.h \
    src/gui/auth/qgsauthenticationutils.h \
    src/gui/auth/qgsauthenticationeditorwidgets.h \
    src/gui/auth/qgsauthenticationcertificateinfo.h \
    src/gui/auth/qgsauthenticationimportcertdialog.h \
    src/core/auth/qgsauthenticationcertutils.h \
    src/gui/auth/qgsauthenticationcerttrustpolicycombobox.h \
    src/gui/auth/qgsauthenticationtrustedcasdialog.h \
    src/gui/auth/qgsauthenticationimportidentitydialog.h \
    src/gui/auth/qgsauthenticationsslconfigwidget.h \
    src/gui/auth/qgsauthenticationsslimportdialog.h

FORMS += \
    src/ui/webpage.ui \
    src/ui/testwidget.ui \
    src/ui/qgsmasterpasswordresetdialog.ui \
    src/ui/qgsauthenticationconfigwidget.ui \
    src/ui/qgsauthenticationconfigeditor.ui \
    src/ui/qgsauthenticationconfigselect.ui \
    src/ui/qgsauthenticationidentitieseditor.ui \
    src/ui/qgsauthenticationauthoritieseditor.ui \
    src/ui/qgsauthenticationserverseditor.ui \
    src/ui/qgsauthenticationeditorwidgets.ui \
    src/ui/qgsauthenticationcertificateinfo.ui \
    src/ui/qgsauthenticationimportcertdialog.ui \
    src/ui/qgsauthenticationtrustedcasdialog.ui \
    src/ui/qgsauthenticationimportidentitydialog.ui \
    src/ui/qgsauthenticationsslconfigwidget.ui \
    src/ui/qgsauthenticationsslimportdialog.ui \
    src/ui/qgsauthenticationsslimporterrors.ui

RESOURCES += images/images.qrc
