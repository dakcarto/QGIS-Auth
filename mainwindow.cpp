#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "qgsauthenticationmanager.h"

MainWindow::MainWindow(QWidget *parent) :
  QMainWindow(parent),
  ui(new Ui::MainWindow)
{
  ui->setupUi(this);

  QgsAuthenticationManager::instance()->initAuthDatabase();
}

MainWindow::~MainWindow()
{
  delete ui;
}
