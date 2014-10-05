#include "qgsauthenticationconfigwidget.h"
#include "ui_qgsauthenticationconfigwidget.h"

#include <QDir>
#include <QFileDialog>
#include <QPushButton>

#include "qgsauthenticationconfig.h"
#include "qgsauthenticationmanager.h"

QgsAuthConfigWidget::QgsAuthConfigWidget( QWidget *parent, const QgsAuthIdPair &authidpair )
    : QDialog( parent )
    , mAuthId( authidpair.first )
    , mAuthIdType( authidpair.second )
    , mAuthIdBase( QgsAuthConfigBase() )
    , mRecentDir( QDir::homePath() )
{

  setupUi( this );

  connect( buttonBox, SIGNAL( rejected() ), this, SLOT( close() ) );
  connect( buttonBox, SIGNAL( accepted() ), this, SLOT( saveConfig() ) );
  connect( buttonBox->button( QDialogButtonBox::Reset ), SIGNAL( clicked() ), this, SLOT( resetConfig() ) );

  cmbAuthProviderType->addItem( tr( "Username/Password" ) );

#ifdef QT_NO_OPENSSL
  stkwProviderType->removeWidget( pagePkiPaths );
#else
  cmbAuthProviderType->addItem( tr( "PKI Certificate" ) );
#endif

  connect( cmbAuthProviderType, SIGNAL( currentIndexChanged( int ) ),
           stkwProviderType, SLOT( setCurrentIndex( int ) ) );
  connect( stkwProviderType, SIGNAL( currentChanged( int ) ),
           cmbAuthProviderType, SLOT( setCurrentIndex( int ) ) );

  cmbAuthProviderType->setCurrentIndex( 0 );
  stkwProviderType->setCurrentIndex( 0 );

  loadConfig();
}

QgsAuthConfigWidget::~QgsAuthConfigWidget()
{
}

void QgsAuthConfigWidget::loadConfig()
{
  // edit mode requires master password to have been set and verified against auth db
  if ( mAuthId.isEmpty() || !QgsAuthManager::instance()->setMasterPassword( true ) )
  {
    return;
  }

  if ( mAuthIdType == QgsAuthType::Basic )
  {
    QgsAuthConfigBasic configbasic;
    if ( QgsAuthManager::instance()->loadAuthenticationConfig( mAuthId, configbasic, true ) )
    {
      if ( configbasic.isValid() )
      {
        leName->setText( configbasic.name() );
        leResource->setText( configbasic.uri() );
        cmbAuthProviderType->setCurrentIndex(( int ) configbasic.type() );

        leBasicUsername->setText( configbasic.username() );
        leBasicPassword->setText( configbasic.password() );
        leBasicRealm->setText( configbasic.realm() );
      }
    }
  }
#ifndef QT_NO_OPENSSL
  else if ( mAuthIdType == QgsAuthType::PkiPaths )
  {
    stkwProviderType->setCurrentIndex( stkwProviderType->indexOf( pagePkiPaths ) );
    QgsAuthConfigPkiPaths configpki;
    if ( QgsAuthManager::instance()->loadAuthenticationConfig( mAuthId, configpki, true ) )
    {
      if ( configpki.isValid() )
      {
        leName->setText( configpki.name() );
        leResource->setText( configpki.uri() );
        cmbAuthProviderType->setCurrentIndex(( int ) configpki.type() );

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
}

void QgsAuthConfigWidget::saveConfig()
{
  // TODO: verify can save

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
      QgsAuthManager::instance()->updateAuthenticationConfig( configbasic );
    }
    else // create new
    {
      QgsAuthManager::instance()->storeAuthenticationConfig( configbasic );
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
      QgsAuthManager::instance()->updateAuthenticationConfig( configpki );
    }
    else // create new
    {
      QgsAuthManager::instance()->storeAuthenticationConfig( configpki );
    }
  }
#endif

  this->accept();
}

void QgsAuthConfigWidget::on_btnClear_clicked()
{
  switch ( cmbAuthProviderType->currentIndex() )
  {
    case 0: // basic
      leBasicUsername->clear();
      leBasicPassword->clear();
      leBasicRealm->clear();
      chkBasicPasswordShow->setChecked( false );
      break;
#ifndef QT_NO_OPENSSL
    case 1: // pki paths
      lePkiPathsCert->clear();
      lePkiPathsKey->clear();
      lePkiPathsKeyPass->clear();
      chkPkiPathsPassShow->setChecked( false );
      lePkiPathsIssuer->clear();
      chkPkiPathsIssuerSelf->setChecked( false );
      break;
#endif
    default:
      break;
  }
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
  lePkiPathsCert->clear();
  lePkiPathsKey->clear();
  lePkiPathsKeyPass->clear();
  chkPkiPathsPassShow->setChecked( false );
  lePkiPathsIssuer->clear();
  chkPkiPathsIssuerSelf->setChecked( false );
#endif
}

void QgsAuthConfigWidget::on_chkBasicPasswordShow_stateChanged( int state )
{
  leBasicPassword->setEchoMode(( state > 0 ) ? QLineEdit::Normal : QLineEdit::Password );
}

QString QgsAuthConfigWidget::getOpenFileName()
{
  QString f = QFileDialog::getOpenFileName( this, tr( "Open PEM File" ), mRecentDir, tr( "PEM (*.pem *.key)" ) );
  if ( !f.isEmpty() )
  {
    mRecentDir = QFileInfo( f ).absoluteDir().path();
  }
  return f;
}

#ifndef QT_NO_OPENSSL
void QgsAuthConfigWidget::on_chkPkiPathsPassShow_stateChanged( int state )
{
  lePkiPathsKeyPass->setEchoMode(( state > 0 ) ? QLineEdit::Normal : QLineEdit::Password );
}

void QgsAuthConfigWidget::on_btnPkiPathsCert_clicked()
{
  const QString& fn = getOpenFileName();
  if ( !fn.isEmpty() )
  {
    lePkiPathsCert->setText( fn );
  }
}

void QgsAuthConfigWidget::on_btnPkiPathsKey_clicked()
{
  const QString& fn = getOpenFileName();
  if ( !fn.isEmpty() )
  {
    lePkiPathsKey->setText( fn );
  }
}

void QgsAuthConfigWidget::on_btnPkiPathsIssuer_clicked()
{
  const QString& fn = getOpenFileName();
  if ( !fn.isEmpty() )
  {
    lePkiPathsIssuer->setText( fn );
  }
}
#endif
