#include <QApplication>

#include "webpage.h"

int main( int argc, char *argv[] )
{
  QApplication a( argc, argv );

  // load default widget
  WebPage * mWebPage = new WebPage();
  mWebPage->show();
  mWebPage->raise();
  mWebPage->activateWindow();

  return a.exec();
}
