#ifndef QGSAUTHENTICATIONCINFIGWIDGET_H
#define QGSAUTHENTICATIONCINFIGWIDGET_H

#include <QDialog>

#include "ui_qgsauthenticationconfigwidget.h"
#include "qgsauthenticationconfig.h"


typedef QPair<QString, QgsAuthType::ProviderType> QgsAuthIdPair;

class QgsAuthConfigWidget : public QDialog, private Ui::QgsAuthConfigWidget
{
    Q_OBJECT

  public:
    explicit QgsAuthConfigWidget( QWidget *parent = 0, const QgsAuthIdPair& authidpair = QgsAuthIdPair() );
    ~QgsAuthConfigWidget();

  private slots:
    void loadConfig();
    void resetConfig();
    void saveConfig();

    void on_btnClear_clicked();
    void clearAll();

    void on_chkBasicPasswordShow_stateChanged( int state );

#ifndef QT_NO_OPENSSL
    void on_chkPkiPathsPassShow_stateChanged( int state );

    void on_btnPkiPathsCert_clicked();

    void on_btnPkiPathsKey_clicked();

    void on_btnPkiPathsIssuer_clicked();
#endif

  private:
    QString getOpenFileName();

    QString mAuthId;
    QgsAuthType::ProviderType mAuthIdType;
    QgsAuthConfigBase mAuthIdBase;
    QString mRecentDir;
};

#endif // QGSAUTHENTICATIONCINFIGWIDGET_H
