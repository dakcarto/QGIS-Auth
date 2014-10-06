#ifndef QGSAUTHENTICATIONCINFIGWIDGET_H
#define QGSAUTHENTICATIONCINFIGWIDGET_H

#include <QDialog>

#include "ui_qgsauthenticationconfigwidget.h"
#include "qgsauthenticationconfig.h"


class QgsAuthConfigWidget : public QDialog, private Ui::QgsAuthConfigWidget
{
    Q_OBJECT

  public:
    enum Validity
    {
      Valid,
      Invalid,
      Unknown
    };

    explicit QgsAuthConfigWidget( QWidget *parent = 0, const QString& authid = QString() );
    ~QgsAuthConfigWidget();

    const QString configId() const { return mAuthId; }

  signals:
    void authenticationConfigStored( const QString& authid );
    void authenticationConfigUpdated( const QString& authid );

  private slots:
    void loadConfig();
    void resetConfig();
    void saveConfig();

    void on_btnClear_clicked();
    void clearAll();

    void validateAuth();

    void on_leName_textChanged( const QString& txt );
    void on_leBasicUsername_textChanged( const QString& txt );
    void on_chkBasicPasswordShow_stateChanged( int state );

#ifndef QT_NO_OPENSSL
    void clearPkiPathsMessage();
    void writePkiPathsMessage( const QString& msg, Validity valid = Unknown );

    void clearPkiPathsCert();

    void clearPkiPathsCertId();
    void clearPkiPathsKeyId();
    void clearPkiPathsKeyPassphrase();
    void clearPkiPathsIssuerId();
    void clearPkiPathsIssuerSelfSigned();

    void on_chkPkiPathsPassShow_stateChanged( int state );

    void on_btnPkiPathsCert_clicked();

    void on_btnPkiPathsKey_clicked();

    void on_btnPkiPathsIssuer_clicked();
#endif

  private:
    bool validateBasic();

#ifndef QT_NO_OPENSSL
    /**
     * @brief Validate certificate and private key combination.
     * @note This is just lightweight validation, and does not traverse the issuer certificate chain
     * @see QSslCertificate.isValid()
     */
    bool validatePkiPaths();
#endif

    int providerIndexByType( QgsAuthType::ProviderType ptype );

    void fileFound( bool found, QWidget * widget );
    QString getOpenFileName( const QString& title, const QString& extfilter );

    QString mAuthId;
};

#endif // QGSAUTHENTICATIONCINFIGWIDGET_H
