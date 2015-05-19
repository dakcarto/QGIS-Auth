/****************************************************************************
**
** Copyright (C) 2014 Digia Plc and/or its subsidiary(-ies).
** Contact: http://www.qt-project.org/legal
**
** This file is part of the examples of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:BSD$
** You may use this file under the terms of the BSD license as follows:
**
** "Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are
** met:
**   * Redistributions of source code must retain the above copyright
**     notice, this list of conditions and the following disclaimer.
**   * Redistributions in binary form must reproduce the above copyright
**     notice, this list of conditions and the following disclaimer in
**     the documentation and/or other materials provided with the
**     distribution.
**   * Neither the name of Digia Plc and its Subsidiary(-ies) nor the names
**     of its contributors may be used to endorse or promote products derived
**     from this software without specific prior written permission.
**
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
** "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
** LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
** A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
** OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
** DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
** THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
** OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."
**
** $QT_END_LICENSE$
**
****************************************************************************/

#include "qgsauthenticationcertificateinfo.h"
#include "qgsauthenticationsslimportdialog.h"
#include "ui_qgsauthenticationsslimporterrors.h"

#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QPushButton>
#include <QScrollBar>
#include <QStyle>
#include <QTimer>
#include <QToolButton>
#include <QSslCipher>

#include "qgslogger.h"


QgsAuthSslImportDialog::QgsAuthSslImportDialog(QWidget *parent)
  : QDialog( parent )
  , mSocket( 0 )
  , mExecErrorsDialog( false )
  , mTimer( 0 )
  , mSslErrors( QList<QSslError>() )
{
  setupUi(this);
  QStyle *style = QApplication::style();
  lblWarningIcon->setPixmap( style->standardIcon( QStyle::SP_MessageBoxWarning ).pixmap( 48, 48 ) );
  lblWarningIcon->setSizePolicy( QSizePolicy::Fixed, QSizePolicy::Fixed );

  closeButton()->setDefault( false );
  saveButton()->setEnabled( false );

  leServer->setSelection(0, leServer->text().size());
  pteSessionStatus->setReadOnly( true );
  spinbxTimeout->setValue( 15 );

  grpbxServer->setCollapsed( false );
  radioServerImport->setChecked( true );
  frameServerImport->setEnabled( true );
  radioFileImport->setChecked( false );
  frameFileImport->setEnabled( false );

  connect( radioServerImport, SIGNAL( toggled( bool ) ),
           this, SLOT( radioServerImportToggled( bool ) ) );
  connect( radioFileImport, SIGNAL( toggled( bool ) ),
           this, SLOT( radioFileImportToggled( bool ) ) );

  connect( leServer, SIGNAL( textChanged( QString ) ),
           this, SLOT( updateEnabledState() ) );
  connect( btnConnect, SIGNAL( clicked() ),
           this, SLOT( secureConnect() ) );
  connect( leServer, SIGNAL( returnPressed() ),
           btnConnect, SLOT( click() ) );

  connect( buttonBox, SIGNAL( accepted() ),
           this, SLOT( accept() ) );
  connect( buttonBox, SIGNAL( rejected() ),
           this, SLOT( reject() ) );

  connect( wdgtSslConfig, SIGNAL( configEnabled( bool ) ),
           this, SLOT( sslConfigEnabled( bool ) ) );
  wdgtSslConfig->setEnabled( false );
}

QgsAuthSslImportDialog::~QgsAuthSslImportDialog()
{
}

void QgsAuthSslImportDialog::accept()
{
  wdgtSslConfig->saveSslCertConfig();
  QDialog::accept();
}

void QgsAuthSslImportDialog::updateEnabledState()
{
  leServer->setStyleSheet( "" );

  bool unconnected = !mSocket || mSocket->state() == QAbstractSocket::UnconnectedState;

  leServer->setReadOnly(!unconnected);
  leServer->setFocusPolicy(unconnected ? Qt::StrongFocus : Qt::NoFocus);

  spinbxTimeout->setReadOnly( !unconnected );

  btnConnect->setEnabled(unconnected && !leServer->text().isEmpty());

  bool connected = mSocket && mSocket->state() == QAbstractSocket::ConnectedState;
  if ( connected && !mSocket->peerName().isEmpty() )
  {
    appendString( tr( "Connected to %1:%2" ).arg( mSocket->peerName() ).arg( mSocket->peerPort() ) );
  }
}

void QgsAuthSslImportDialog::secureConnect()
{
  if ( leServer->text().isEmpty() )
  {
    return;
  }

  leServer->setStyleSheet( "" );
  clearStatusCertificateConfig();

  if (!mSocket) {
    mSocket = new QSslSocket(this);
    connect(mSocket, SIGNAL(stateChanged(QAbstractSocket::SocketState)),
            this, SLOT(socketStateChanged(QAbstractSocket::SocketState)));
    connect(mSocket, SIGNAL(encrypted()),
            this, SLOT(socketEncrypted()));
    connect(mSocket, SIGNAL(sslErrors(QList<QSslError>)),
            this, SLOT(sslErrors(QList<QSslError>)));
    connect(mSocket, SIGNAL(readyRead()),
            this, SLOT(socketReadyRead()));
  }

  if ( !mTimer )
  {
    mTimer = new QTimer( this );
    connect( mTimer, SIGNAL( timeout() ), this, SLOT( destroySocket() ) );
  }
  mTimer->start( spinbxTimeout->value() * 1000 );

  mSocket->connectToHostEncrypted(leServer->text(), spinbxPort->value());
  updateEnabledState();
}

void QgsAuthSslImportDialog::socketStateChanged( QAbstractSocket::SocketState state )
{
  if ( mExecErrorsDialog )
  {
    return;
  }

  updateEnabledState();
  if ( state == QAbstractSocket::UnconnectedState )
  {
    leServer->setFocus();
    destroySocket();
  }
}

void QgsAuthSslImportDialog::socketEncrypted()
{
  if (!mSocket)
    return;  // might have disconnected already

  appendString( tr( "Socket ENCRYPTED" ) );

  appendString( QString( "%1: %2" ).arg( tr( "Protocol" ) )
                .arg( QgsAuthCertUtils::getSslProtocolName( mSocket->protocol() ) ) );

  QSslCipher ciph = mSocket->sessionCipher();
  QString cipher = QString("%1: %2, %3 (%4/%5)")
      .arg( tr( "Session cipher" ) ).arg(ciph.authenticationMethod())
      .arg(ciph.name()).arg(ciph.usedBits()).arg(ciph.supportedBits());
  appendString( cipher );



  wdgtSslConfig->setEnabled( true );
  wdgtSslConfig->setSslCertificate( mSocket->peerCertificate() );
  wdgtSslConfig->setSslHost( QString( "%1:%2" ).arg( mSocket->peerName() ).arg( mSocket->peerPort() ) );
  if ( !mSslErrors.isEmpty() )
  {
    wdgtSslConfig->appendSslIgnoreErrors( mSslErrors );
    mSslErrors.clear();
  }

  // must come after last state change, or gets reverted
  leServer->setStyleSheet( QgsAuthCertUtils::greenTextStyleSheet() );

  destroySocket();
}

void QgsAuthSslImportDialog::socketReadyRead()
{
  appendString( QString::fromUtf8( mSocket->readAll() ) );
}

void QgsAuthSslImportDialog::destroySocket()
{
  if ( !mSocket )
  {
    return;
  }
  if ( !mSocket->isEncrypted() )
  {
    appendString( tr( "Socket unavailable or not encrypted" ) );
  }
  mSocket->disconnectFromHost();
  appendString( tr( "Connection to host stopped" ) );
  mSocket->deleteLater();
  mSocket = 0;
}

void QgsAuthSslImportDialog::sslErrors( const QList<QSslError> &errors )
{
  if ( !mTimer->isActive() )
  {
   return;
  }
  mTimer->stop();

  QDialog errorDialog( this );
  Ui_SslErrors ui;
  ui.setupUi(&errorDialog);
  connect( ui.certificateChainButton, SIGNAL( clicked() ),
           this, SLOT( showCertificateInfo() ) );

  foreach ( const QSslError &error, errors)
  {
    ui.sslErrorList->addItem(error.errorString());
  }

  mExecErrorsDialog = true;
  if ( errorDialog.exec() == QDialog::Accepted )
  {
      mSocket->ignoreSslErrors();
      mSslErrors = errors;
  }
  mExecErrorsDialog = false;

  mTimer->start();

  // did the socket state change?
  if ( mSocket->state() != QAbstractSocket::ConnectedState )
      socketStateChanged( mSocket->state() );
}

void QgsAuthSslImportDialog::showCertificateInfo()
{
  QList<QSslCertificate> peerchain( mSocket->peerCertificateChain() );

  if ( !peerchain.isEmpty() )
  {
    QSslCertificate cert = peerchain.takeFirst();
    if ( !cert.isNull() )
    {
      QgsAuthCertInfoDialog *info = new QgsAuthCertInfoDialog(cert, false, this, peerchain );
      info->exec();
      info->deleteLater();
    }
  }
}

void QgsAuthSslImportDialog::sslConfigEnabled( bool checked )
{
  saveButton()->setEnabled( checked );
  saveButton()->setDefault( false );
  closeButton()->setDefault( false );
}

void QgsAuthSslImportDialog::radioServerImportToggled( bool checked )
{
  frameServerImport->setEnabled( checked );
  clearStatusCertificateConfig();
}

void QgsAuthSslImportDialog::radioFileImportToggled(bool checked)
{
  frameFileImport->setEnabled( checked );
  clearStatusCertificateConfig();
}

void QgsAuthSslImportDialog::on_btnCertPath_clicked()
{
  const QString& fn = getOpenFileName( tr( "Open Server Certificate File" ),  tr( "PEM (*.pem);;DER (*.der)" ) );
  if ( !fn.isEmpty() )
  {
    leCertPath->setText( fn );
    loadCertFromFile();
  }
}

void QgsAuthSslImportDialog::clearCertificateConfig()
{
  wdgtSslConfig->resetSslCertConfig();
  wdgtSslConfig->setEnabled( false );
}

void QgsAuthSslImportDialog::clearStatusCertificateConfig()
{
  mSslErrors.clear();
  pteSessionStatus->clear();
  clearCertificateConfig();
}

void QgsAuthSslImportDialog::loadCertFromFile()
{
  clearStatusCertificateConfig();
  QList<QSslCertificate> certs( QgsAuthCertUtils::certsFromFile( leCertPath->text() ) );

  if ( certs.isEmpty() )
  {
    appendString( tr( "Could not load any certs from file" ) );
    return;
  }

  QSslCertificate cert( certs.first() );
  if ( cert.isNull() )
  {
    appendString( tr( "Could not load server cert from file" ) );
    return;
  }

  if ( !QgsAuthCertUtils::certificateIsSslServer( cert ) )
  {
    appendString( tr( "Certificate does not appear for be for an SSL server" ) );
    return;
  }

  wdgtSslConfig->setEnabled( true );
  wdgtSslConfig->setSslHost( "" );
  wdgtSslConfig->setSslCertificate( cert );
  if ( wdgtSslConfig->sslHost().isEmpty() )
  {
    // no config was loaded, default to wildcard
    wdgtSslConfig->setSslHost( "*" );
  }
  if ( !mSslErrors.isEmpty() )
  {
    wdgtSslConfig->appendSslIgnoreErrors( mSslErrors );
    mSslErrors.clear();
  }
}

void QgsAuthSslImportDialog::appendString( const QString &line )
{
  QTextCursor cursor( pteSessionStatus->textCursor() );
  cursor.movePosition( QTextCursor::End );
  cursor.insertText( line + "\n" );
//  pteSessionStatus->verticalScrollBar()->setValue( pteSessionStatus->verticalScrollBar()->maximum() );
}

QPushButton *QgsAuthSslImportDialog::saveButton()
{
  return buttonBox->button( QDialogButtonBox::Save );
}

QPushButton *QgsAuthSslImportDialog::closeButton()
{
  return buttonBox->button( QDialogButtonBox::Close );
}

QString QgsAuthSslImportDialog::getOpenFileName(const QString &title, const QString &extfilter)
{
  QSettings settings;
  QString recentdir = settings.value( "UI/lastAuthImportSslOpenFileDir", QDir::homePath() ).toString();
  QString f = QFileDialog::getOpenFileName( this, title, recentdir, extfilter );

  // return dialog focus on Mac
  this->raise();
  this->activateWindow();

  if ( !f.isEmpty() )
  {
    settings.setValue( "UI/lastAuthImportSslOpenFileDir", QFileInfo( f ).absoluteDir().path() );
  }
  return f;
}
