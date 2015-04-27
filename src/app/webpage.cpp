/***************************************************************************
    webpage.cpp  -  test app for PKI integration in QGIS
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

#include "webpage.h"
#include "ui_webpage.h"

#include "testwidget.h"

#include <QDialog>
#include <QDir>
#include <QInputDialog>
#include <QLineEdit>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslError>
#include <QSslKey>

#include "qgsauthenticationmanager.h"
#include "qgsauthenticationeditorwidgets.h"
#include "qgsauthenticationconfigselect.h"
#include "qgsauthenticationconfigwidget.h"


WebPage::WebPage( QWidget *parent )
    : QDialog( parent )
    , mPage( 0 )
    , mNaMan( 0 )
    , mReply( 0 )
    , mLoaded( false )
    , mTestWidget( 0 )
{
  setupUi( this );

  comboBox->lineEdit()->setAlignment( Qt::AlignLeft );

  QStringList urlList;
  urlList << "http://localhost"
  << QString( "http://localhost:8080" )
  << QString( "https://localhost:8443" )
  << QString( "https://localhost:8443/geoserver/web/" )
  << QString( "http://www.google.com" )
  << QString( "https://localhost:8443/geoserver/opengeo/wms?service=WMS&version=1.1.0"
              "&request=GetMap&layers=opengeo:countries&styles=&bbox=-180.0,-90.0,180.0,90.0"
              "&width=720&height=400&srs=EPSG:4326&format=application/openlayers" );

  comboBox->addItems( urlList );

  setWebPage();

  connect( webView, SIGNAL( linkClicked( QUrl ) ), this, SLOT( loadUrl( QUrl ) ) );
  connect( webView, SIGNAL( urlChanged( QUrl ) ), this, SLOT( setLocation( QUrl ) ) );
  connect( webView, SIGNAL( titleChanged( const QString& ) ), SLOT( updateTitle( const QString& ) ) );

  connect( backButton, SIGNAL( clicked() ), webView, SLOT( back() ) );
  connect( forwardButton, SIGNAL( clicked() ), webView, SLOT( forward() ) );
  connect( reloadButton, SIGNAL( clicked() ), webView, SLOT( reload() ) );
  connect( stopButton, SIGNAL( clicked() ), webView, SLOT( stop() ) );

//  connect( comboBox->lineEdit(), SIGNAL( returnPressed() ), this, SLOT( loadUrl() ) );
  connect( comboBox, SIGNAL( activated( const QString& ) ), this, SLOT( loadUrl( const QString& ) ) );
  connect( clearButton, SIGNAL( clicked() ), this, SLOT( clearLog() ) );

  connect( this, SIGNAL( messageOut( const QString&, const QString&, MessageLevel ) ),
           this, SLOT( writeDebug( const QString&, const QString&, MessageLevel ) ) );

  QgsAuthManager::instance()->init();
}

WebPage::~WebPage()
{
}

void WebPage::updateTitle( const QString& title )
{
  setWindowTitle( title );
}

void WebPage::setLocation( const QUrl& url )
{
  comboBox->lineEdit()->setText( url.toString() );
}

void WebPage::appendLog( const QString& msg )
{
  plainTextEdit->appendPlainText( msg );
}

void WebPage::clearLog()
{
  plainTextEdit->clear();
}

void WebPage::showEvent( QShowEvent * e )
{
  if ( !mLoaded )
  {
    loadUrl();
    mLoaded = true;
  }

  QDialog::showEvent( e );
}

void WebPage::loadUrl( const QString& url )
{
  QString curText( comboBox->lineEdit()->text() );
  if ( url.isEmpty() && curText.isEmpty() )
  {
    return;
  }

  QUrl reqUrl( url.isEmpty() ? comboBox->lineEdit()->text() : url );
  loadUrl( reqUrl );
}

void WebPage::loadUrl( const QUrl& url )
{
  if ( url.isEmpty() || !url.isValid() )
  {
    return;
  }

  QNetworkRequest req;
  req.setUrl( url );
  req.setRawHeader( "User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:32.0) Gecko/20100101 Firefox/32.0" );

  if ( !leAuthId->text().isEmpty() )
    QgsAuthManager::instance()->updateNetworkRequest( req, leAuthId->text() );

  //webView->load( req ); // hey, why doesn't this work? doesn't pass ssl cert/key

  if ( mReply )
    mReply->deleteLater();
  mReply = 0;

  mReply = mNaMan->get( req );

  if ( !leAuthId->text().isEmpty() )
    QgsAuthManager::instance()->updateNetworkReply( mReply, leAuthId->text() );

  clearWebView();
  setLocation( mReply->request().url() );
  webView->setFocus();
  connect( mReply, SIGNAL( readyRead() ), this, SLOT( loadReply() ) );
}

void WebPage::loadReply()
{
  QUrl url( mReply->url() );
  webView->setContent( mReply->readAll(), QString(), url );
}

void WebPage::setWebPage()
{
  mNaMan->deleteLater();
  mPage = new QWebPage( this );
  webView->setPage( mPage );

  mNaMan = mPage->networkAccessManager();

  connect( mNaMan, SIGNAL( finished( QNetworkReply* ) ), this, SLOT( requestReply( QNetworkReply* ) ) );
  connect(
    mNaMan, SIGNAL( sslErrors( QNetworkReply*, const QList<QSslError>& ) ),
    this, SLOT( onSslErrors( QNetworkReply*, const QList<QSslError>& ) )
  );
}

void WebPage::clearWebView()
{
  webView->setContent( 0 );
}

void WebPage::requestReply( QNetworkReply * reply )
{
  if ( reply->error() != QNetworkReply::NoError )
  {
    appendLog( QString( "Network error #%1: %2" ).arg( reply->error() ).arg( reply->errorString() ) );
  }
}

void WebPage::onSslErrors( QNetworkReply* reply, const QList<QSslError>& errors )
{
//  reply->ignoreSslErrors( expectedSslErrors() );

  QString msg = QString( "SSL errors occured accessing URL %1:" ).arg( reply->request().url().toString() );

  foreach ( const QSslError& error, errors )
  {
    if ( error.error() == QSslError::NoError )
      continue;

    msg += "\n" + error.errorString();
  }

  appendLog( msg );
}

void WebPage::on_btnResetWebView_clicked()
{
  setWebPage();
  loadUrl();
}

void WebPage::on_btnAuthSettings_clicked()
{
  QDialog * dlg = new QDialog( 0 );
  dlg->setWindowTitle( tr( "Authentication Settings" ) );
  QVBoxLayout *layout = new QVBoxLayout( dlg );

  QgsAuthEditorWidgets * ae = new QgsAuthEditorWidgets( dlg );
  layout->addWidget( ae );

  QDialogButtonBox *buttonBox = new QDialogButtonBox( QDialogButtonBox::Close,
      Qt::Horizontal, dlg );
  buttonBox->button( QDialogButtonBox::Close )->setDefault( true );

  layout->addWidget( buttonBox );

  connect( buttonBox, SIGNAL( rejected() ), dlg, SLOT( close() ) );

  dlg->setLayout( layout );
  dlg->setWindowModality( Qt::WindowModal );
  dlg->resize(700, 500);
  dlg->exec();

}

void WebPage::on_btnAuthSelect_clicked()
{
  QDialog * dlg = new QDialog( 0 );
  dlg->setWindowTitle( tr( "Select Authentication" ) );
  QVBoxLayout *layout = new QVBoxLayout( dlg );

  QgsAuthConfigSelect * as = new QgsAuthConfigSelect( dlg );
  if ( !leAuthId->text().isEmpty() )
    as->setConfigId( leAuthId->text() );
  layout->addWidget( as );

  QDialogButtonBox *buttonBox = new QDialogButtonBox(
    QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
    Qt::Horizontal, dlg );
  layout->addWidget( buttonBox );

  connect( buttonBox, SIGNAL( accepted() ), dlg, SLOT( accept() ) );
  connect( buttonBox, SIGNAL( rejected() ), dlg, SLOT( close() ) );

  dlg->setLayout( layout );
  dlg->setWindowModality( Qt::WindowModal );
  if ( dlg->exec() )
  {
    emit messageOut( QString( "Selected authid: %1" ).arg( as->configId() ) );
    leAuthId->setText( as->configId() );
  }
  else
  {
    emit messageOut( "QgsAuthConfigWidget->exec() = 0" );
  }
}

void WebPage::on_btnTests_clicked()
{
  if ( !mTestWidget )
  {
    mTestWidget = new TestWidget();
    mTestWidget->setWindowModality( Qt::WindowModal );
  }
  mTestWidget->show();
}

//void WebPage::on_btnAuthConfigEdit_clicked()
//{
//  if ( !QgsAuthManager::instance()->setMasterPassword( true ) )
//    return;

//  QgsAuthConfigWidget * aw = new QgsAuthConfigWidget( "rk28j52", 0 );
//  aw->setWindowModality( Qt::WindowModal );
//  connect( aw, SIGNAL( authenticationConfigStored( const QString& ) ),
//           this, SIGNAL( messageOut( const QString& ) ) );
//  connect( aw, SIGNAL( authenticationConfigUpdated( const QString& ) ),
//           this, SIGNAL( messageOut( const QString& ) ) );
//  if ( aw->exec() )
//  {
//    emit messageOut( QString( "Update authid: %1" ).arg( aw->configId() ) );
//  }
//  else
//  {
//    emit messageOut( "QgsAuthConfigWidget->exec() = 0" );
//  }
//}

void WebPage::on_btnAuthClearCached_clicked()
{
  if ( !leAuthId->text().isEmpty() )
    QgsAuthManager::instance()->clearCachedConfig( leAuthId->text() );
}

void WebPage::writeDebug( const QString& message, const QString& tag, WebPage::MessageLevel level )
{
  Q_UNUSED( tag );

  QString msg;
  switch ( level )
  {
    case INFO:
      break;
    case WARNING:
      msg += "WARNING: ";
      break;
    case CRITICAL:
      msg += "ERROR: ";
      break;
    default:
      break;
  }

  if ( !tag.isEmpty() )
  {
    msg += QString( "( %1 ) " ).arg( tag );
  }

  msg += message;
  qDebug( "%s", msg.toLatin1().constData() );
}
