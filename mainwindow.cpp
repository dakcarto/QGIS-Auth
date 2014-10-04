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

  QgsAuthManager::instance()->init();

  connect( QgsAuthManager::instance(), SIGNAL( masterPasswordVerified( bool ) ),
           this, SLOT( masterPasswordVerificationChanged( bool ) ) );

  lePassword->setText( "mypassword" );

  setButtonTexts();
}

MainWindow::~MainWindow()
{
}

void MainWindow::masterPasswordVerificationChanged( bool verified )
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
      QgsAuthCrypto::encrypt( pass, in, "AES" ) );
  }
}

void MainWindow::on_teEncryptCrypt_textChanged()
{
  QString pass = lePassword->text();
  QString crypt( teEncryptCrypt->toPlainText() );
  if ( !pass.isEmpty() && !crypt.isEmpty() )
  {
    teEncryptOut->setPlainText(
      QgsAuthCrypto::decrypt( pass, crypt, "AES" ) );
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
//  QgsAuthManager::instance()->inputMasterPassword();
//  teOut->appendPlainText( QgsAuthManager::instance()->uniqueConfigId() );

//  QgsAuthCrypto::passwordHash( lePassword->text(), &mSalt, &mHash );
//  teOut->appendPlainText( QString( "Salt: %1\nHash: %2" ).arg( mSalt ).arg( mHash ) );

  QgsAuthManager::instance()->setMasterPassword();
}

void MainWindow::on_btnTwo_clicked()
{
//  QString derived;
//  bool ok = QgsAuthCrypto::verifyPasswordHash( lePassword->text(), mSalt, mHash, &derived );
//  teOut->appendPlainText( QString( "Hash verified: %1" ).arg( ok ? "yes" : "no" ) );
//  teOut->appendPlainText( QString( "Derived hash: %1" ).arg( derived ) );

  QgsAuthManager::instance()->setMasterPassword( true );
}

void MainWindow::on_btnThree_clicked()
{
//  QString derived;
//  bool ok = QgsAuthCrypto::verifyPasswordHash( lePassword->text(), "OH58VEVT", mHash, &derived );
//  teOut->appendPlainText( QString( "Hash verified (bad salt): %1" ).arg( ok ? "yes" : "no" ) );
//  teOut->appendPlainText( QString( "Derived hash (bad salt): %1" ).arg( derived ) );

//  ok = QgsAuthCrypto::verifyPasswordHash( "nonsene", mSalt, mHash, &derived );
//  teOut->appendPlainText( QString( "Hash verified (bad pass): %1" ).arg( ok ? "yes" : "no" ) );
//  teOut->appendPlainText( QString( "Derived hash (bad pass): %1" ).arg( derived ) );

  QgsAuthManager::instance()->resetMasterPassword();
}

void MainWindow::on_btnFour_clicked()
{
  QgsAuthManager::instance()->clearMasterPassword();
}
