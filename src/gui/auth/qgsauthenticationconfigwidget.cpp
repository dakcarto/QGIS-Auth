/***************************************************************************
    qgsauthenticationconfigwidget.cpp
    ---------------------
    begin                : October 5, 2014
    copyright            : (C) 2014 by Boundless Spatial, Inc. USA
    author               : Larry Shaffer
    email                : lshaffer at boundlessgeo dot com
 ***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include "qgsauthenticationconfigwidget.h"
#include "ui_qgsauthenticationconfigwidget.h"

#include <QDateTime>
#include <QDir>
#include <QFileDialog>
#include <QPushButton>
#include <QSettings>
#ifndef QT_NO_OPENSSL
#include <QSslCertificate>
#include <QSslKey>
#include <QtCrypto>
#endif

#include "qgsapplication.h"
#include "qgsauthenticationcertutils.h"
#include "qgsauthenticationconfig.h"
#include "qgsauthenticationmanager.h"
#include "qgslogger.h"


QgsAuthConfigWidget::QgsAuthConfigWidget( QWidget *parent , const QString& authcfg )
    : QDialog( parent )
    , mAuthCfg( authcfg )
    , mAuthNotifyLayout( 0 )
    , mAuthNotify( 0 )
{
  if ( QgsAuthManager::instance()->isDisabled() )
  {
    mAuthNotifyLayout = new QVBoxLayout;
    this->setLayout( mAuthNotifyLayout );
    QString msg( QgsAuthManager::instance()->disabledMessage() );
    if ( !authcfg.isEmpty() )
    {
      msg += "\n\n" + tr( "Authentication config id not loaded: %1" ).arg( authcfg );
    }
    mAuthNotify = new QLabel( msg, this );
    mAuthNotifyLayout->addWidget( mAuthNotify );

    mAuthCfg.clear(); // otherwise will contiue to try authenticate (and fail) after save
  }
  else
  {
    setupUi( this );
    connect( buttonBox, SIGNAL( rejected() ), this, SLOT( close() ) );
    connect( buttonBox, SIGNAL( accepted() ), this, SLOT( saveConfig() ) );
    connect( buttonBox->button( QDialogButtonBox::Reset ), SIGNAL( clicked() ), this, SLOT( resetConfig() ) );

    cmbAuthProviderType->addItem( tr( "Username/Password" ), QVariant( QgsAuthType::Basic ) );

#ifdef QT_NO_OPENSSL
    stkwProviderType->removeWidget( pagePkiPaths );
    stkwProviderType->removeWidget( pagePkiPkcs12 );
    stkwProviderType->removeWidget( pageIdentityCert );
#else
    cmbAuthProviderType->addItem( tr( "PKI PEM/DER Certificate Paths" ), QVariant( QgsAuthType::PkiPaths ) );
    cmbAuthProviderType->addItem( tr( "PKI PKCS#12 Certificate Bundle" ), QVariant( QgsAuthType::PkiPkcs12 ) );
    cmbAuthProviderType->addItem( tr( "Stored Identity Certificate" ), QVariant( QgsAuthType::IdentityCert ) );
    populateIdentityComboBox();
#endif

    connect( cmbAuthProviderType, SIGNAL( currentIndexChanged( int ) ),
             stkwProviderType, SLOT( setCurrentIndex( int ) ) );
    connect( stkwProviderType, SIGNAL( currentChanged( int ) ),
             cmbAuthProviderType, SLOT( setCurrentIndex( int ) ) );

    connect( cmbAuthProviderType, SIGNAL( currentIndexChanged( int ) ),
             this, SLOT( validateAuth() ) );
    connect( stkwProviderType, SIGNAL( currentChanged( int ) ),
             this, SLOT( validateAuth() ) );

    cmbAuthProviderType->setCurrentIndex( 0 );
    stkwProviderType->setCurrentIndex( 0 );

    loadConfig();
    validateAuth();

    leName->setFocus();
  }
}

QgsAuthConfigWidget::~QgsAuthConfigWidget()
{
}

void QgsAuthConfigWidget::loadConfig()
{
  if ( mAuthCfg.isEmpty() )
  {
    return;
  }

  QgsAuthType::ProviderType authtype = QgsAuthManager::instance()->configProviderType( mAuthCfg );

  QgsDebugMsg( QString( "Loading auth id: %1" ).arg( mAuthCfg ) );
  QgsDebugMsg( QString( "Loading auth type: %1" ).arg( QgsAuthType::typeToString( authtype ) ) );

  if ( authtype == QgsAuthType::None || authtype == QgsAuthType::Unknown )
    return;

  // edit mode requires master password to have been set and verified against auth db
  if ( !QgsAuthManager::instance()->setMasterPassword( true ) )
    return;

  int indx = providerIndexByType( authtype );
  if ( indx == -1 )
    return;

  cmbAuthProviderType->setCurrentIndex( indx );

  if ( authtype == QgsAuthType::Basic )
  {
    QgsAuthConfigBasic configbasic;
    if ( QgsAuthManager::instance()->loadAuthenticationConfig( mAuthCfg, configbasic, true ) )
    {
      if ( configbasic.isValid() && configbasic.type() != QgsAuthType::Unknown )
      {
        leName->setText( configbasic.name() );
        leResource->setText( configbasic.uri() );
        leAuthCfg->setText( configbasic.id() );

        leBasicUsername->setText( configbasic.username() );
        leBasicPassword->setText( configbasic.password() );
        leBasicRealm->setText( configbasic.realm() );
      }
    }
  }
#ifndef QT_NO_OPENSSL
  else if ( authtype == QgsAuthType::PkiPaths )
  {
    stkwProviderType->setCurrentIndex( stkwProviderType->indexOf( pagePkiPaths ) );
    QgsAuthConfigPkiPaths configpki;
    if ( QgsAuthManager::instance()->loadAuthenticationConfig( mAuthCfg, configpki, true ) )
    {
      if ( configpki.isValid() && configpki.type() != QgsAuthType::Unknown )
      {
        leName->setText( configpki.name() );
        leResource->setText( configpki.uri() );
        leAuthCfg->setText( configpki.id() );

        lePkiPathsCert->setText( configpki.certId() );
        lePkiPathsKey->setText( configpki.keyId() );
        lePkiPathsKeyPass->setText( configpki.keyPassphrase() );
      }
      //QgsDebugMsg( configpki.certAsPem() );
      //QgsDebugMsg( configpki.keyAsPem( false ).first() );
      //QgsDebugMsg( configpki.keyAsPem( true ).first() );
    }
  }
  else if ( authtype == QgsAuthType::PkiPkcs12 )
  {
    stkwProviderType->setCurrentIndex( stkwProviderType->indexOf( pagePkiPkcs12 ) );
    QgsAuthConfigPkiPkcs12 configpkcs;
    if ( QgsAuthManager::instance()->loadAuthenticationConfig( mAuthCfg, configpkcs, true ) )
    {
      if ( configpkcs.isValid() && configpkcs.type() != QgsAuthType::Unknown )
      {
        leName->setText( configpkcs.name() );
        leResource->setText( configpkcs.uri() );
        leAuthCfg->setText( configpkcs.id() );

        lePkiPkcs12Bundle->setText( configpkcs.bundlePath() );
        lePkiPkcs12KeyPass->setText( configpkcs.bundlePassphrase() );
      }
      //QgsDebugMsg( configpkcs.certAsPem() );
      //QgsDebugMsg( configpkcs.keyAsPem( false ).first()  );
      //QgsDebugMsg( configpkcs.keyAsPem( true ).first() );
    }
  }
  else if ( authtype == QgsAuthType::IdentityCert )
  {
    stkwProviderType->setCurrentIndex( stkwProviderType->indexOf( pageIdentityCert ) );
    QgsAuthConfigIdentityCert configident;
    if ( QgsAuthManager::instance()->loadAuthenticationConfig( mAuthCfg, configident, true ) )
    {
      if ( configident.isValid() && configident.type() != QgsAuthType::Unknown )
      {
        leName->setText( configident.name() );
        leResource->setText( configident.uri() );
        leAuthCfg->setText( configident.id() );

        int indx = cmbIdentityCert->findData( configident.certId() );
        cmbIdentityCert->setCurrentIndex( indx == -1 ? 0 : indx );
      }
      //QgsDebugMsg( configident.certAsPem() );
      //QgsDebugMsg( configident.keyAsPem( false ).first() );
    }
  }
#endif
}

void QgsAuthConfigWidget::resetConfig()
{
  clearAll();
  loadConfig();
  validateAuth();
}

void QgsAuthConfigWidget::saveConfig()
{
  if ( !QgsAuthManager::instance()->setMasterPassword( true ) )
    return;

  QWidget *curpage = stkwProviderType->currentWidget();
  if ( curpage == pageBasic ) // basic
  {
    QgsAuthConfigBasic configbasic;
    configbasic.setName( leName->text() );
    configbasic.setUri( leResource->text() );

    configbasic.setUsername( leBasicUsername->text() );
    configbasic.setPassword( leBasicPassword->text() );
    configbasic.setRealm( leBasicRealm->text() );

    if ( !mAuthCfg.isEmpty() ) // update
    {
      configbasic.setId( mAuthCfg );
      if ( QgsAuthManager::instance()->updateAuthenticationConfig( configbasic ) )
      {
        emit authenticationConfigUpdated( mAuthCfg );
      }
    }
    else // create new
    {
      if ( QgsAuthManager::instance()->storeAuthenticationConfig( configbasic ) )
      {
        mAuthCfg = configbasic.id();
        emit authenticationConfigStored( mAuthCfg );
      }
    }
  }
#ifndef QT_NO_OPENSSL
  else if ( curpage == pagePkiPaths ) // pki paths
  {
    QgsAuthConfigPkiPaths configpki;
    configpki.setName( leName->text() );
    configpki.setUri( leResource->text() );

    configpki.setCertId( lePkiPathsCert->text() );
    configpki.setKeyId( lePkiPathsKey->text() );
    configpki.setKeyPassphrase( lePkiPathsKeyPass->text() );

    if ( !mAuthCfg.isEmpty() ) // update
    {
      configpki.setId( mAuthCfg );
      if ( QgsAuthManager::instance()->updateAuthenticationConfig( configpki ) )
      {
        emit authenticationConfigUpdated( mAuthCfg );
      }
    }
    else // create new
    {
      if ( QgsAuthManager::instance()->storeAuthenticationConfig( configpki ) )
      {
        mAuthCfg = configpki.id();
        emit authenticationConfigStored( mAuthCfg );
      }
    }
  }
  else if ( curpage == pagePkiPkcs12 ) // pki pkcs#12 bundle
  {
    QgsAuthConfigPkiPkcs12 configpkcs;
    configpkcs.setName( leName->text() );
    configpkcs.setUri( leResource->text() );

    configpkcs.setBundlePath( lePkiPkcs12Bundle->text() );
    configpkcs.setBundlePassphrase( lePkiPkcs12KeyPass->text() );

    if ( !mAuthCfg.isEmpty() ) // update
    {
      configpkcs.setId( mAuthCfg );
      if ( QgsAuthManager::instance()->updateAuthenticationConfig( configpkcs ) )
      {
        emit authenticationConfigUpdated( mAuthCfg );
      }
    }
    else // create new
    {
      if ( QgsAuthManager::instance()->storeAuthenticationConfig( configpkcs ) )
      {
        mAuthCfg = configpkcs.id();
        emit authenticationConfigStored( mAuthCfg );
      }
    }
  }
  else if ( curpage == pageIdentityCert ) // identity certificate
  {
    QgsAuthConfigIdentityCert configident;
    configident.setName( leName->text() );
    configident.setUri( leResource->text() );

    configident.setCertId( cmbIdentityCert->itemData( cmbIdentityCert->currentIndex() ).toString() );

    if ( !mAuthCfg.isEmpty() ) // update
    {
      configident.setId( mAuthCfg );
      if ( QgsAuthManager::instance()->updateAuthenticationConfig( configident ) )
      {
        emit authenticationConfigUpdated( mAuthCfg );
      }
    }
    else // create new
    {
      if ( QgsAuthManager::instance()->storeAuthenticationConfig( configident ) )
      {
        mAuthCfg = configident.id();
        emit authenticationConfigStored( mAuthCfg );
      }
    }
  }
#endif

  this->accept();
}

void QgsAuthConfigWidget::on_btnClear_clicked()
{
  QWidget *curpage = stkwProviderType->currentWidget();
  if ( curpage == pageBasic )
  {
    clearAuthBasic();
  }
#ifndef QT_NO_OPENSSL
  else if ( curpage == pagePkiPaths )
  {
    clearPkiPathsCert();
  }
  else if ( curpage == pagePkiPkcs12 )
  {
    clearPkiPkcs12Bundle();
  }
  else if ( curpage == pageIdentityCert )
  {
    clearIdentityCert();
  }
#endif
  validateAuth();
}

void QgsAuthConfigWidget::clearAll()
{
  leName->clear();
  leResource->clear();
  leAuthCfg->clear();

  // basic
  clearAuthBasic();

#ifndef QT_NO_OPENSSL
  // pki paths
  clearPkiPathsCert();
  // pki pkcs#12
  clearPkiPkcs12Bundle();
  // identity cert
  clearIdentityCert();
#endif

  validateAuth();
}

void QgsAuthConfigWidget::validateAuth()
{
  bool authok = !leName->text().isEmpty();

  QWidget *curpage = stkwProviderType->currentWidget();
  if ( curpage == pageBasic )
  {
    authok = authok && validateBasic();
  }
#ifndef QT_NO_OPENSSL
  else if ( curpage == pagePkiPaths )
  {
    authok = authok && validatePkiPaths();
  }
  else if ( curpage == pagePkiPkcs12 )
  {
    authok = authok && validatePkiPkcs12();
  }
  else if ( curpage == pageIdentityCert )
  {
    authok = authok && validateIdentityCert();
  }
#endif
  buttonBox->button( QDialogButtonBox::Save )->setEnabled( authok );
}

void QgsAuthConfigWidget::on_leName_textChanged( const QString& txt )
{
  Q_UNUSED( txt );
  validateAuth();
}

int QgsAuthConfigWidget::providerIndexByType( QgsAuthType::ProviderType ptype )
{
  return cmbAuthProviderType->findData( QVariant( ptype ) );
}

void QgsAuthConfigWidget::fileFound( bool found, QWidget *widget )
{
  if ( !found )
  {
    widget->setStyleSheet( QgsAuthCertUtils::redTextStyleSheet( "QLineEdit" ) );
    widget->setToolTip( tr( "File not found" ) );
  }
  else
  {
    widget->setStyleSheet( "" );
    widget->setToolTip( "" );
  }
}

QString QgsAuthConfigWidget::getOpenFileName( const QString& title, const QString& extfilter )
{
  QSettings settings;
  QString recentdir = settings.value( "UI/lastAuthConfigWidgetOpenFileDir", QDir::homePath() ).toString();
  QString f = QFileDialog::getOpenFileName( this, title, recentdir, extfilter );
  if ( !f.isEmpty() )
  {
    settings.setValue( "UI/lastAuthConfigWidgetOpenFileDir", QFileInfo( f ).absoluteDir().path() );
  }
  return f;
}

//////////////////////////////////////////////////////
// Auth Basic
//////////////////////////////////////////////////////

void QgsAuthConfigWidget::clearAuthBasic()
{
  leBasicUsername->clear();
  leBasicPassword->clear();
  leBasicRealm->clear();
  chkBasicPasswordShow->setChecked( false );
}

void QgsAuthConfigWidget::on_leBasicUsername_textChanged( const QString& txt )
{
  Q_UNUSED( txt );
  validateAuth();
}

void QgsAuthConfigWidget::on_chkBasicPasswordShow_stateChanged( int state )
{
  leBasicPassword->setEchoMode(( state > 0 ) ? QLineEdit::Normal : QLineEdit::Password );
}

bool QgsAuthConfigWidget::validateBasic()
{
  return !leBasicUsername->text().isEmpty();
}


//////// PKI below that requires Qt to be built with runtime OpenSSL support ////////////////

#ifndef QT_NO_OPENSSL

// Shared functions

void QgsAuthConfigWidget::clearPkiMessage( QLineEdit *lineedit )
{
  lineedit->clear();
  lineedit->setStyleSheet( "" );
}

void QgsAuthConfigWidget::writePkiMessage( QLineEdit *lineedit, const QString &msg, QgsAuthConfigWidget::Validity valid )
{
  QString ss;
  QString txt( msg );
  switch ( valid )
  {
    case Valid:
      ss = QgsAuthCertUtils::greenTextStyleSheet( "QLineEdit" );
      txt = tr( "Valid: %1" ).arg( msg );
      break;
    case Invalid:
      ss = QgsAuthCertUtils::redTextStyleSheet( "QLineEdit" );
      txt = tr( "Invalid: %1" ).arg( msg );
      break;
    case Unknown:
      ss = "";
      break;
    default:
      ss = "";
  }
  lineedit->setStyleSheet( ss );
  lineedit->setText( txt );
  lineedit->setCursorPosition( 0 );
}

//////////////////////////////////////////////////////
// Auth PkiPaths
//////////////////////////////////////////////////////

void QgsAuthConfigWidget::clearPkiPathsCert()
{
  clearPkiPathsCertId();
  clearPkiPathsKeyId();
  clearPkiPathsKeyPassphrase();

  clearPkiMessage( lePkiPathsMsg );
  validateAuth();
}

void QgsAuthConfigWidget::clearPkiPathsCertId()
{
  lePkiPathsCert->clear();
  lePkiPathsCert->setStyleSheet( "" );
}

void QgsAuthConfigWidget::clearPkiPathsKeyId()
{
  lePkiPathsKey->clear();
  lePkiPathsKey->setStyleSheet( "" );
}

void QgsAuthConfigWidget::clearPkiPathsKeyPassphrase()
{
  lePkiPathsKeyPass->clear();
  lePkiPathsKeyPass->setStyleSheet( "" );
}

bool QgsAuthConfigWidget::validatePkiPaths()
{
  bool certvalid = false;

  // required components
  QString certpath( lePkiPathsCert->text() );
  QString keypath( lePkiPathsKey->text() );

  bool certfound = QFile::exists( certpath );
  bool keyfound = QFile::exists( keypath );

  fileFound( certpath.isEmpty() || certfound, lePkiPathsCert );
  fileFound( keypath.isEmpty() || keyfound, lePkiPathsKey );

  if ( !certfound || !keyfound )
  {
    writePkiMessage( lePkiPathsMsg, tr( "Missing components" ), Invalid );
    return false;
  }

  // check for issue date validity, then notify status
  QSslCertificate cert;
  QFile file( certpath );
  QFileInfo fileinfo( file );
  QString ext( fileinfo.fileName().replace( fileinfo.completeBaseName(), "" ).toLower() );
  if ( ext.isEmpty() )
  {
    writePkiMessage( lePkiPathsMsg, tr( "Certificate file has no extension" ), Invalid );
    return false;
  }

  QFile::OpenMode openflags( QIODevice::ReadOnly );
  QSsl::EncodingFormat encformat( QSsl::Der );
  if ( ext == ".pem" )
  {
    openflags |= QIODevice::Text;
    encformat = QSsl::Pem;
  }

  if ( file.open( openflags ) )
  {
    cert = QSslCertificate( file.readAll(), encformat );
    file.close();
  }
  else
  {
    writePkiMessage( lePkiPathsMsg, tr( "Failed to read certificate file" ), Invalid );
    return false;
  }

  if ( cert.isNull() )
  {
    writePkiMessage( lePkiPathsMsg, tr( "Failed to load certificate from file" ), Invalid );
    return false;
  }

  certvalid = cert.isValid();
  QDateTime startdate( cert.effectiveDate() );
  QDateTime enddate( cert.expiryDate() );

  writePkiMessage( lePkiPathsMsg,
                   tr( "%1 thru %2" ).arg( startdate.toString() ).arg( enddate.toString() ),
                   ( certvalid ? Valid : Invalid ) );

  return certvalid;
}

void QgsAuthConfigWidget::on_chkPkiPathsPassShow_stateChanged( int state )
{
  lePkiPathsKeyPass->setEchoMode(( state > 0 ) ? QLineEdit::Normal : QLineEdit::Password );
}

void QgsAuthConfigWidget::on_btnPkiPathsCert_clicked()
{
  const QString& fn = getOpenFileName( tr( "Open Client Certificate File" ),  tr( "PEM (*.pem);;DER (*.der)" ) );
  if ( !fn.isEmpty() )
  {
    lePkiPathsCert->setText( fn );
    validateAuth();
  }
}

void QgsAuthConfigWidget::on_btnPkiPathsKey_clicked()
{
  const QString& fn = getOpenFileName( tr( "Open Private Key File" ),  tr( "PEM (*.pem);;DER (*.der)" ) );
  if ( !fn.isEmpty() )
  {
    lePkiPathsKey->setText( fn );
    validateAuth();
  }
}

//////////////////////////////////////////////////////
// Auth PkiPkcs#12
//////////////////////////////////////////////////////

void QgsAuthConfigWidget::clearPkiPkcs12Bundle()
{
  clearPkiPkcs12BundlePath();
  clearPkiPkcs12KeyPassphrase();

  clearPkiMessage( lePkiPkcs12Msg );
  validateAuth();
}

void QgsAuthConfigWidget::clearPkiPkcs12BundlePath()
{
  lePkiPkcs12Bundle->clear();
  lePkiPkcs12Bundle->setStyleSheet( "" );
}

void QgsAuthConfigWidget::clearPkiPkcs12KeyPassphrase()
{
  lePkiPkcs12KeyPass->clear();
  lePkiPkcs12KeyPass->setStyleSheet( "" );
  lePkiPkcs12KeyPass->setPlaceholderText( QString( "Optional passphrase" ) );
}

bool QgsAuthConfigWidget::validatePkiPkcs12()
{
  // required components
  QString bundlepath( lePkiPkcs12Bundle->text() );

  bool bundlefound = QFile::exists( bundlepath );

  fileFound( bundlepath.isEmpty() || bundlefound, lePkiPkcs12Bundle );

  if ( !bundlefound )
  {
    writePkiMessage( lePkiPkcs12Msg, tr( "Missing components" ), Invalid );
    return false;
  }

  if ( !QCA::isSupported( "pkcs12" ) )
  {
    writePkiMessage( lePkiPkcs12Msg, tr( "QCA library has no PKCS#12 support" ), Invalid );
    return false;
  }

  // load the bundle
  QCA::SecureArray passarray;
  if ( !lePkiPkcs12KeyPass->text().isEmpty() )
    passarray = QCA::SecureArray( lePkiPkcs12KeyPass->text().toUtf8() );

  QCA::ConvertResult res;
  QCA::KeyBundle bundle( QCA::KeyBundle::fromFile( bundlepath, passarray, &res, QString( "qca-ossl" ) ) );

  if ( res == QCA::ErrorFile )
  {
    writePkiMessage( lePkiPkcs12Msg, tr( "Failed to read bundle file" ), Invalid );
    return false;
  }
  else if ( res == QCA::ErrorPassphrase )
  {
    writePkiMessage( lePkiPkcs12Msg, tr( "Incorrect bundle password" ), Invalid );
    lePkiPkcs12KeyPass->setPlaceholderText( QString( "Required passphrase" ) );
    return false;
  }
  else if ( res == QCA::ErrorDecode )
  {
    writePkiMessage( lePkiPkcs12Msg, tr( "Failed to decode (try entering password)" ), Invalid );
    return false;
  }

  if ( bundle.isNull() )
  {
    writePkiMessage( lePkiPkcs12Msg, tr( "Bundle empty or can not be loaded" ), Invalid );
    return false;
  }

  // check for primary cert and that it is valid
  QCA::Certificate cert( bundle.certificateChain().primary() );
  if ( cert.isNull() )
  {
    writePkiMessage( lePkiPkcs12Msg, tr( "Bundle client cert can not be loaded" ), Invalid );
    return false;
  }

  // TODO: add more robust validation, including cert chain resolution
  QDateTime startdate( cert.notValidBefore() );
  QDateTime enddate( cert.notValidAfter() );
  QDateTime now( QDateTime::currentDateTime() );
  bool bundlevalid = ( now >= startdate && now <= enddate );

  writePkiMessage( lePkiPkcs12Msg,
                   tr( "%1 thru %2" ).arg( startdate.toString() ).arg( enddate.toString() ),
                   ( bundlevalid ? Valid : Invalid ) );

  return bundlevalid;
}

void QgsAuthConfigWidget::on_lePkiPkcs12KeyPass_textChanged( const QString &pass )
{
  Q_UNUSED( pass );
  validateAuth();
}

void QgsAuthConfigWidget::on_chkPkiPkcs12PassShow_stateChanged( int state )
{
  lePkiPkcs12KeyPass->setEchoMode(( state > 0 ) ? QLineEdit::Normal : QLineEdit::Password );
}

void QgsAuthConfigWidget::on_btnPkiPkcs12Bundle_clicked()
{
  const QString& fn = getOpenFileName( tr( "Open PKCS#12 Certificate Bundle" ),  tr( "PKCS#12 (*.p12 *.pfx)" ) );
  if ( !fn.isEmpty() )
  {
    lePkiPkcs12Bundle->setText( fn );
    validateAuth();
  }
}

//////////////////////////////////////////////////////
// Auth Identity Cert
//////////////////////////////////////////////////////

bool QgsAuthConfigWidget::validateIdentityCert()
{
  return cmbIdentityCert->currentIndex() != 0;
}

void QgsAuthConfigWidget::populateIdentityComboBox()
{
  cmbIdentityCert->addItem( tr( "Select identity..." ) );

  QList<QSslCertificate> certs( QgsAuthManager::instance()->getCertIdentities() );
  if ( !certs.isEmpty() )
  {
    cmbIdentityCert->setIconSize( QSize( 26, 22 ) );
    QMap<QString, QString> idents;
    Q_FOREACH( const QSslCertificate& cert, certs )
    {
      QString org( cert.subjectInfo( QSslCertificate::Organization ) );
      if ( org.isEmpty() )
        org = tr( "Organization not defined" );
      idents.insert( QString( "%1 (%2)" ).arg( QgsAuthCertUtils::resolvedCertName( cert ) ).arg( org ),
                     QgsAuthCertUtils::shaHexForCert( cert ) );
    }
    QMap<QString, QString>::const_iterator it = idents.constBegin();
    for ( ; it != idents.constEnd(); ++it )
    {
      cmbIdentityCert->addItem( QgsApplication::getThemeIcon( "/mIconCertificate.svg"),
                                it.key(), it.value() );
    }
  }
}

void QgsAuthConfigWidget::clearIdentityCert()
{
  cmbIdentityCert->setCurrentIndex( 0 );
}

void QgsAuthConfigWidget::on_cmbIdentityCert_currentIndexChanged( int indx )
{
  Q_UNUSED( indx );
  validateAuth();
}

#endif
