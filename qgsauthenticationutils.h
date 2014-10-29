#ifndef QGSAUTHENTICATIONUTILS_H
#define QGSAUTHENTICATIONUTILS_H

#include <QDialog>

#include "ui_qgsmasterpasswordresetdialog.h"

class QgsMasterPasswordResetDialog : public QDialog, private Ui::QgsMasterPasswordResetDialog
{
    Q_OBJECT

  public:
    explicit QgsMasterPasswordResetDialog( QWidget *parent = 0 );
    ~QgsMasterPasswordResetDialog();

    bool requestMasterPasswordReset( QString *password, bool *keepbackup );

  private slots:
    void on_leMasterPassCurrent_textChanged( const QString& pass );
    void on_leMasterPassNew_textChanged( const QString& pass );

    void on_chkPassShowCurrent_stateChanged( int state );
    void on_chkPassShowNew_stateChanged( int state );

  private:
    void validatePasswords();

    bool mPassCurOk;
    bool mPassNewOk;
};

#endif // QGSAUTHENTICATIONUTILS_H
