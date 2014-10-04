/***************************************************************************
    webpage.h  -  test app for PKI integration in QGIS
                             -------------------
    begin                : 2014-09-12
    copyright            : (C) 2014 by Boundless Spatial, Inc.
    web                  : http://boundlessgeo.com
    author               : Larry Shaffer
    email                : larrys at dakotacarto dot com
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#ifndef WEBPAGE_H
#define WEBPAGE_H

#include "ui_webpage.h"
#include "testwidget.h"

#include <QDialog>
#include <QNetworkAccessManager>
#include <QSslCertificate>

#include "qgsauthenticationconfigeditor.h"


class WebPage : public QDialog, private Ui::WebPage
{
  Q_OBJECT

  public:
    explicit WebPage( QWidget *parent = 0 );
    ~WebPage();

  protected:
    void showEvent( QShowEvent * );

  private slots:
    void requestReply( QNetworkReply* reply );
    void onSslErrors( QNetworkReply* reply, const QList<QSslError>& errors );
    void updateTitle( const QString& title );
    void setLocation( const QUrl& url );
    void loadUrl( const QString& url = QString() );
    void loadUrl( const QUrl& url );
    void loadReply();
    void clearWebView();
    void clearLog();

    void on_btnAuth_clicked();
    void on_btnTests_clicked();

  private:
    void appendLog( const QString& msg );
    QSslCertificate certAuth();
    QSslCertificate clientCert();
    QSslKey clientKey( const QByteArray& passphrase );
    QList<QSslError> expectedSslErrors();
    QString pkiDir();

    QNetworkAccessManager *mNaMan;
    QNetworkReply *mReply;
    bool mLoaded;

    TestWidget *mTestWidget;
    QgsAuthConfigEditor *mAuthSelector;
};

#endif // WEBPAGE_H
