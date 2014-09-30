#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "qgsauthenticationconfig.h"
#include "qgsauthenticationcrypto.h"
#include "qgsauthenticationmanager.h"

MainWindow::MainWindow( QWidget *parent )
  : QMainWindow( parent )
{
  setupUi( this );
  QgsAuthenticationManager::instance()->initAuthDatabase();

  lePassword->setText( "mypassword" );
}

MainWindow::~MainWindow()
{
}

void MainWindow::on_teEncryptIn_textChanged()
{
  QString pass( lePassword->text() );
  QString in( teEncryptIn->toPlainText() );
  if ( !pass.isEmpty() && !in.isEmpty()  )
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

void MainWindow::on_btnOne_clicked()
{
//  QgsAuthenticationManager::instance()->inputMasterPassword();
  teOut->appendPlainText( QgsAuthenticationManager::instance()->uniqueConfigId() );
}

void MainWindow::on_btnTwo_clicked()
{
  QString salt;
  QString hash;
  QgsAuthenticationCrypto::passwordHash( lePassword->text(), &salt, &hash );
  teOut->appendPlainText( QString( "Salt: %1\nHash: %2" ).arg( salt ).arg( hash ) );
}
