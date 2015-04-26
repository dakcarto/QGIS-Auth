#ifndef TESTWIDGET_H
#define TESTWIDGET_H

#include "ui_testwidget.h"

class TestWidget : public QWidget, private Ui::TestWidget
{
    Q_OBJECT

  public:
    explicit TestWidget( QWidget *parent = 0 );
    ~TestWidget();

  private slots:
    void masterPasswordVerificationChanged( bool verified );

    void on_teEncryptIn_textChanged();
    void on_teEncryptCrypt_textChanged();

    void setButtonTexts();

    void on_btnOne_clicked();
    void on_btnTwo_clicked();
    void on_btnThree_clicked();
    void on_btnFour_clicked();

  private:
    QString mSalt;
    QString mHash;
    QString mCiv;
};

#endif // TESTWIDGET_H
