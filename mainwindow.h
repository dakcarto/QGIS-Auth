#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include "ui_mainwindow.h"

class MainWindow : public QMainWindow, private Ui::MainWindow
{
    Q_OBJECT

  public:
    explicit MainWindow( QWidget *parent = 0 );
    ~MainWindow();

  private slots:
    void on_teEncryptIn_textChanged();
    void on_teEncryptCrypt_textChanged();
    void on_btnOne_clicked();
    void on_btnTwo_clicked();
    void on_btnThree_clicked();

  private:
    QString mSalt;
    QString mHash;
};

#endif // MAINWINDOW_H
