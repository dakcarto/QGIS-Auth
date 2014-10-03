#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QFileInfo>

#include "qgsapplication.h"
#include "qgsauthenticationconfig.h"
#include "qgsauthenticationcrypto.h"
#include "qgsauthenticationmanager.h"

MainWindow::MainWindow( QWidget *parent )
    : QMainWindow( parent )
    , mSalt( QString() )
    , mHash( QString() )
{
  setupUi( this );

//  QFile f( QgsApplication::qgisAuthDbFilePath() );
//  if ( f.exists(  ) )
//  {
//    f.remove();
//  }

  QgsAuthenticationManager::instance()->init();

  connect( QgsAuthenticationManager::instance(), SIGNAL( masterPasswordVerified( bool ) ),
           this, SLOT( masterPasswordVerificationChanged( bool ) ) );

  lePassword->setText( "mypassword" );

  setButtonTexts();
}

MainWindow::~MainWindow()
{
}

void MainWindow::masterPasswordVerificationChanged(bool verified)
{
  teOut->appendPlainText( QString( "Master password is %1" ).arg( verified ? "verified" : "not verified" ) );
}

void MainWindow::on_teEncryptIn_textChanged()
{
  QString pass( lePassword->text() );
  QString in( teEncryptIn->toPlainText() );
  if ( !pass.isEmpty() && !in.isEmpty() )
  {
    teEncryptCrypt->setPlainText(
      QgsAuthenticationCrypto::encrypt( pass, in, "AES" ) );
  }
}

void MainWindow::on_teEncryptCrypt_textChanged()
{
  QString pass = lePassword->text();
  QString crypt( teEncryptCrypt->toPlainText() );
  if ( !pass.isEmpty() && !crypt.isEmpty() )
  {
    teEncryptOut->setPlainText(
      QgsAuthenticationCrypto::decrypt( pass, crypt, "AES" ) );
  }
}

void MainWindow::setButtonTexts()
{
  btnOne->setText( "Set master" );
  btnTwo->setText( "Reset master" );
  btnThree->setText( "Reset master" );
  btnFour->setText( "Clear master" );
}



void MainWindow::on_btnOne_clicked()
{
//  QgsAuthenticationManager::instance()->inputMasterPassword();
//  teOut->appendPlainText( QgsAuthenticationManager::instance()->uniqueConfigId() );

//  QgsAuthenticationCrypto::passwordHash( lePassword->text(), &mSalt, &mHash );
//  teOut->appendPlainText( QString( "Salt: %1\nHash: %2" ).arg( mSalt ).arg( mHash ) );

  QgsAuthenticationManager::instance()->setMasterPassword();
}

void MainWindow::on_btnTwo_clicked()
{
//  QString derived;
//  bool ok = QgsAuthenticationCrypto::verifyPasswordHash( lePassword->text(), mSalt, mHash, &derived );
//  teOut->appendPlainText( QString( "Hash verified: %1" ).arg( ok ? "yes" : "no" ) );
//  teOut->appendPlainText( QString( "Derived hash: %1" ).arg( derived ) );

  QgsAuthenticationManager::instance()->setMasterPassword( true );
}

void MainWindow::on_btnThree_clicked()
{
//  QString derived;
//  bool ok = QgsAuthenticationCrypto::verifyPasswordHash( lePassword->text(), "OH58VEVT", mHash, &derived );
//  teOut->appendPlainText( QString( "Hash verified (bad salt): %1" ).arg( ok ? "yes" : "no" ) );
//  teOut->appendPlainText( QString( "Derived hash (bad salt): %1" ).arg( derived ) );

//  ok = QgsAuthenticationCrypto::verifyPasswordHash( "nonsene", mSalt, mHash, &derived );
//  teOut->appendPlainText( QString( "Hash verified (bad pass): %1" ).arg( ok ? "yes" : "no" ) );
//  teOut->appendPlainText( QString( "Derived hash (bad pass): %1" ).arg( derived ) );

  QgsAuthenticationManager::instance()->resetMasterPassword();
}

void MainWindow::on_btnFour_clicked()
{
  QgsAuthenticationManager::instance()->clearMasterPassword();
}
