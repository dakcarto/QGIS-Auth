#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "qgsauthenticationconfig.h"
#include "qgsauthenticationencrypt.h"
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
          QgsAuthenticationEncrypt::encrypt( pass, in, "AES" ) );
  }
}

void MainWindow::on_teEncryptCrypt_textChanged()
{
  QString pass = lePassword->text();
  QString crypt( teEncryptCrypt->toPlainText() );
  if ( !pass.isEmpty() && !crypt.isEmpty() )
  {
    teEncryptOut->setPlainText(
          QgsAuthenticationEncrypt::decrypt( pass, crypt, "AES" ) );
  }
}

void MainWindow::on_btnOne_clicked()
{
//  QgsAuthenticationManager::instance()->inputMasterPassword();
  teOut->appendPlainText( QgsAuthenticationManager::instance()->generateConfigId() );
}
