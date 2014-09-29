#include "mainwindow.h"
#include <QApplication>

int main(int argc, char *argv[])
{
  QApplication a(argc, argv);
  QMainWindow * w = new MainWindow();
  w->show();
  w->raise();
  w->activateWindow();

  return a.exec();
}
