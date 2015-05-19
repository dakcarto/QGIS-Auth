#include <QApplication>
#include <QDialog>

#include "webpage.h"
#include "qgsauthenticationeditorwidgets.h"

int main( int argc, char *argv[] )
{
  QApplication app( argc, argv );

  // load default widget
//  WebPage * mWebPage = new WebPage();
//  mWebPage->show();
//  mWebPage->raise();
//  mWebPage->activateWindow();
//  mWebPage->resize(1000, 800);

  // open Auth Settings for testing
  QgsAuthManager::instance()->init();

  QDialog * dlg = new QDialog( 0 );
  dlg->setWindowTitle( QObject::tr( "Authentication Settings" ) );
  QVBoxLayout *layout = new QVBoxLayout( dlg );

  QgsAuthEditorWidgets * ae = new QgsAuthEditorWidgets( dlg );
  layout->addWidget( ae );

  QDialogButtonBox *buttonBox = new QDialogButtonBox( QDialogButtonBox::Close,
      Qt::Horizontal, dlg );
  buttonBox->button( QDialogButtonBox::Close )->setDefault( true );
  layout->addWidget( buttonBox );
  QObject::connect( buttonBox, SIGNAL( rejected() ), dlg, SLOT( close() ) );

  dlg->setLayout( layout );
  dlg->show();
  // indexes:  configs:0, identities:1, servers:2, authorities:3
  ae->tabbedWidget()->setCurrentIndex( 2 );
  dlg->raise();
  dlg->activateWindow();
  dlg->resize( 800, 512 );

  return app.exec();
}
