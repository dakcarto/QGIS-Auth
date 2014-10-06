#include "qgsauthenticationconfigwidget.h"
#include "ui_qgsauthenticationconfigwidget.h"

#include <QDateTime>
#include <QDir>
#include <QFileDialog>
#include <QPushButton>
#include <QSettings>
#include <QSslCertificate>
#include <QSslKey>

#include "qgsauthenticationconfig.h"
#include "qgsauthenticationmanager.h"

static QString validGreen_( const QString& selector = "*" )
{
  return QString( "%1{color: rgb(0, 170, 0);}" ).arg( selector );
}
static QString validRed_( const QString& selector = "*" )
{
  return QString( "%1{color: rgb(200, 0, 0);}" ).arg( selector );
}

QgsAuthConfigWidget::QgsAuthConfigWidget( QWidget *parent , const QString& authid )
    : QDialog( parent )
    , mAuthId( authid )
{

  setupUi( this );

  connect( buttonBox, SIGNAL( rejected() ), this, SLOT( close() ) );
  connect( buttonBox, SIGNAL( accepted() ), this, SLOT( saveConfig() ) );
  connect( buttonBox->button( QDialogButtonBox::Reset ), SIGNAL( clicked() ), this, SLOT( resetConfig() ) );

  cmbAuthProviderType->addItem( tr( "Username/Password" ), QVariant( QgsAuthType::Basic ) );

#ifdef QT_NO_OPENSSL
  stkwProviderType->removeWidget( pagePkiPaths );
#else
  cmbAuthProviderType->addItem( tr( "PKI Certificate" ), QVariant( QgsAuthType::PkiPaths ) );
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
}

QgsAuthConfigWidget::~QgsAuthConfigWidget()
{
}

void QgsAuthConfigWidget::loadConfig()
{
  if ( mAuthId.isEmpty() )
    return;

  QgsAuthType::ProviderType authtype = QgsAuthManager::instance()->configProviderType( mAuthId );

  qDebug( "Loading auth id: %s", mAuthId.toAscii().constData() );
  qDebug( "Loading auth type: %s", QgsAuthType::typeToString( authtype ).toAscii().constData() );

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
    if ( QgsAuthManager::instance()->loadAuthenticationConfig( mAuthId, configbasic, true ) )
    {
      if ( configbasic.isValid() && configbasic.type() != QgsAuthType::Unknown )
      {
        leName->setText( configbasic.name() );
        leResource->setText( configbasic.uri() );

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
    if ( QgsAuthManager::instance()->loadAuthenticationConfig( mAuthId, configpki, true ) )
    {
      if ( configpki.isValid() && configpki.type() != QgsAuthType::Unknown )
      {
        leName->setText( configpki.name() );
        leResource->setText( configpki.uri() );

        lePkiPathsCert->setText( configpki.certId() );
        lePkiPathsKey->setText( configpki.keyId() );
        lePkiPathsKeyPass->setText( configpki.keyPassphrase() );
        lePkiPathsIssuer->setText( configpki.issuerId() );
        chkPkiPathsIssuerSelf->setChecked( configpki.issuerSelfSigned() );
      }
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

    if ( !mAuthId.isEmpty() ) // update
    {
      configbasic.setId( mAuthId );
      if ( QgsAuthManager::instance()->updateAuthenticationConfig( configbasic ) )
      {
        emit authenticationConfigUpdated( mAuthId );
      }
    }
    else // create new
    {
      if ( QgsAuthManager::instance()->storeAuthenticationConfig( configbasic ) )
      {
        mAuthId = configbasic.id();
        emit authenticationConfigStored( mAuthId );
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
    configpki.setIssuerId( lePkiPathsIssuer->text() );
    configpki.setIssuerSelfSigned( chkPkiPathsIssuerSelf->isChecked() );

    if ( !mAuthId.isEmpty() ) // update
    {
      configpki.setId( mAuthId );
      if ( QgsAuthManager::instance()->updateAuthenticationConfig( configpki ) )
      {
        emit authenticationConfigUpdated( mAuthId );
      }
    }
    else // create new
    {
      if ( QgsAuthManager::instance()->storeAuthenticationConfig( configpki ) )
      {
        mAuthId = configpki.id();
        emit authenticationConfigStored( mAuthId );
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
    leBasicUsername->clear();
    leBasicPassword->clear();
    leBasicRealm->clear();
    chkBasicPasswordShow->setChecked( false );
  }
#ifndef QT_NO_OPENSSL
  else if ( curpage == pagePkiPaths )
  {
    clearPkiPathsCert();
  }
#endif
  validateAuth();
}

void QgsAuthConfigWidget::clearAll()
{
  leName->clear();
  leResource->clear();

  // basic
  leBasicUsername->clear();
  leBasicPassword->clear();
  leBasicRealm->clear();
  chkBasicPasswordShow->setChecked( false );

#ifndef QT_NO_OPENSSL
  // pki paths
  clearPkiPathsCert();
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
#endif
  buttonBox->button( QDialogButtonBox::Save )->setEnabled( authok );
}

void QgsAuthConfigWidget::on_leName_textChanged( const QString& txt )
{
  Q_UNUSED( txt );
  validateAuth();
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

int QgsAuthConfigWidget::providerIndexByType( QgsAuthType::ProviderType ptype )
{
  return cmbAuthProviderType->findData( QVariant( ptype ) );
}

void QgsAuthConfigWidget::fileFound( bool found, QWidget *widget )
{
  if ( !found )
  {
    widget->setStyleSheet( validRed_( "QLineEdit" ) );
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
  QString recentdir = settings.value( "UI/lastPkiPathsOpenFileDir", QDir::homePath() ).toString();
  QString f = QFileDialog::getOpenFileName( this, title, recentdir, extfilter );
  if ( !f.isEmpty() )
  {
    settings.setValue( "UI/lastPkiPathsOpenFileDir", QFileInfo( f ).absoluteDir().path() );
  }
  return f;
}

#ifndef QT_NO_OPENSSL
void QgsAuthConfigWidget::clearPkiPathsMessage()
{
  lePkiPathsMsg->clear();
  lePkiPathsMsg->setStyleSheet( "" );
}

void QgsAuthConfigWidget::writePkiPathsMessage( const QString &msg, QgsAuthConfigWidget::Validity valid )
{
  QString ss;
  QString txt( msg );
  switch ( valid )
  {
    case Valid:
      ss = validGreen_( "QLineEdit" );
      txt = tr( "Valid: %1" ).arg( msg );
      break;
    case Invalid:
      ss = validRed_( "QLineEdit" );
      txt = tr( "Invalid: %1" ).arg( msg );
      break;
    case Unknown:
      ss = "";
      break;
    default:
      ss = "";
  }
  lePkiPathsMsg->setStyleSheet( ss );
  lePkiPathsMsg->setText( txt );
  lePkiPathsMsg->setCursorPosition( 0 );
}

void QgsAuthConfigWidget::clearPkiPathsCert()
{
  clearPkiPathsCertId();
  clearPkiPathsKeyId();
  clearPkiPathsKeyPassphrase();
  clearPkiPathsIssuerId();
  clearPkiPathsIssuerSelfSigned();

  clearPkiPathsMessage();
}

void QgsAuthConfigWidget::clearPkiPathsCertId()
{
  lePkiPathsCert->clear();
  lePkiPathsCert->setStyleSheet( "" );
  validateAuth();
}

void QgsAuthConfigWidget::clearPkiPathsKeyId()
{
  lePkiPathsKey->clear();
  lePkiPathsKey->setStyleSheet( "" );
  validateAuth();
}

void QgsAuthConfigWidget::clearPkiPathsKeyPassphrase()
{
  lePkiPathsKeyPass->clear();
  lePkiPathsKeyPass->setStyleSheet( "" );
  validateAuth();
}

void QgsAuthConfigWidget::clearPkiPathsIssuerId()
{
  lePkiPathsIssuer->clear();
  lePkiPathsIssuer->setStyleSheet( "" );
  validateAuth();
}

void QgsAuthConfigWidget::clearPkiPathsIssuerSelfSigned()
{
  chkPkiPathsIssuerSelf->setChecked( false );
  validateAuth();
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
    writePkiPathsMessage( tr( "Missing cert/key components" ), Invalid );
    return false;
  }

  // check for issue date validity, then notify status
  QSslCertificate cert;
  QFile file( certpath );
  if ( file.open( QIODevice::ReadOnly | QIODevice::Text ) )
  {
    cert = QSslCertificate( file.readAll(), QSsl::Pem );
    file.close();
  }
  else
  {
    writePkiPathsMessage( tr( "Failed to read certificate file" ), Invalid );
    return false;
  }

  certvalid = cert.isValid();
  QDateTime startDate( cert.effectiveDate() );
  QDateTime endDate( cert.expiryDate() );

  writePkiPathsMessage( tr( "%1 thru %2" ).arg( startDate.toString() ).arg( endDate.toString() ),
                        ( certvalid ? Valid : Invalid ) );

  return certvalid;
}

void QgsAuthConfigWidget::on_chkPkiPathsPassShow_stateChanged( int state )
{
  lePkiPathsKeyPass->setEchoMode(( state > 0 ) ? QLineEdit::Normal : QLineEdit::Password );
}

void QgsAuthConfigWidget::on_btnPkiPathsCert_clicked()
{
  const QString& fn = getOpenFileName( tr( "Open PEM File" ),  tr( "PEM (*.pem)" ) );
  if ( !fn.isEmpty() )
  {
    lePkiPathsCert->setText( fn );
    validateAuth();
  }
}

void QgsAuthConfigWidget::on_btnPkiPathsKey_clicked()
{
  const QString& fn = getOpenFileName( tr( "Open PEM File" ),  tr( "PEM (*.pem *.key)" ) );
  if ( !fn.isEmpty() )
  {
    lePkiPathsKey->setText( fn );
    validateAuth();
  }
}

void QgsAuthConfigWidget::on_btnPkiPathsIssuer_clicked()
{
  const QString& fn = getOpenFileName( tr( "Open PEM File" ),  tr( "PEM (*.pem)" ) );
  if ( !fn.isEmpty() )
  {
    lePkiPathsIssuer->setText( fn );
    validateAuth();
  }
}
#endif
