#include "qgsauthenticationutils.h"

#include <QLineEdit>
#include <QMessageBox>
#include <QObject>
#include <QPushButton>

#include "qgsauthenticationmanager.h"


static QString validGreen_( const QString& selector = "QLineEdit" )
{
  return QString( "%1{color: rgb(0, 170, 0);}" ).arg( selector );
}
static QString validRed_( const QString& selector = "QLineEdit" )
{
  return QString( "%1{color: rgb(200, 0, 0);}" ).arg( selector );
}

QgsMasterPasswordResetDialog::QgsMasterPasswordResetDialog( QWidget *parent )
    : QDialog( parent )
    , mPassCurOk( false )
    , mPassNewOk( false )
{
  setupUi( this );
}

QgsMasterPasswordResetDialog::~QgsMasterPasswordResetDialog()
{
}

bool QgsMasterPasswordResetDialog::requestMasterPasswordReset( QString *password, bool *keepbackup )
{
  validatePasswords();
  leMasterPassCurrent->setFocus();

  bool ok = ( exec() == QDialog::Accepted );
  //QgsDebugMsg( QString( "exec(): %1" ).arg( ok ? "true" : "false" ) );

  if ( ok )
  {
    *password = leMasterPassNew->text();
    *keepbackup = chkKeepBackup->isChecked();
    return true;
  }
  return false;
}

void QgsMasterPasswordResetDialog::on_leMasterPassCurrent_textChanged( const QString& pass )
{
  // since this is called on every keystroke, block signals emitted during verification of password
  QgsAuthManager::instance()->blockSignals( true );
  mPassCurOk = !pass.isEmpty() && QgsAuthManager::instance()->setMasterPassword( pass, true );
  QgsAuthManager::instance()->blockSignals( false );
  validatePasswords();
}

void QgsMasterPasswordResetDialog::on_leMasterPassNew_textChanged( const QString& pass )
{
  mPassNewOk = !pass.isEmpty() && !QgsAuthManager::instance()->masterPasswordSame( pass );
  validatePasswords();
}

void QgsMasterPasswordResetDialog::on_chkPassShowCurrent_stateChanged( int state )
{
  leMasterPassCurrent->setEchoMode(( state > 0 ) ? QLineEdit::Normal : QLineEdit::Password );
}

void QgsMasterPasswordResetDialog::on_chkPassShowNew_stateChanged( int state )
{
  leMasterPassNew->setEchoMode(( state > 0 ) ? QLineEdit::Normal : QLineEdit::Password );
}

void QgsMasterPasswordResetDialog::validatePasswords()
{
  leMasterPassCurrent->setStyleSheet( mPassCurOk ? validGreen_() : validRed_() );
  leMasterPassNew->setStyleSheet( mPassNewOk ? validGreen_() : validRed_() );
  buttonBox->button( QDialogButtonBox::Ok )->setEnabled( mPassCurOk && mPassNewOk );
}
