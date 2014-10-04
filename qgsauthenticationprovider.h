#ifndef QGSAUTHENTICATIONPROVIDER_H
#define QGSAUTHENTICATIONPROVIDER_H

#include <QObject>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QUrl>

#ifndef QT_NO_OPENSSL
#include <QSslCertificate>
#include <QSslKey>
#endif

#include "qgsauthenticationconfig.h"

class QgsAuthenticationProvider : public QObject
{
    Q_OBJECT
  public:
    // TODO: switch to QgsMessageLog enum
    enum MessageLevel
    {
      INFO = 0,
      WARNING = 1,
      CRITICAL = 2
    };

    explicit QgsAuthenticationProvider( QObject *parent = 0 ,
                                        QgsAuthenticationConfigBase::ProviderType providertype = QgsAuthenticationConfigBase::None );

    virtual ~QgsAuthenticationProvider();

    QgsAuthenticationConfigBase::ProviderType providerType() const { return mType; }

    static QgsAuthenticationConfigBase::ProviderType providerTypeFromInt( int itype );

    static const QString typeAsString( QgsAuthenticationConfigBase::ProviderType providertype = QgsAuthenticationConfigBase::None );

    static bool urlToResource( const QString& accessurl, QString *resource, bool withpath = false );

    virtual void updateNetworkRequest( QNetworkRequest &request, const QString& authid ) = 0;

    virtual void updateNetworkReply( QNetworkReply *reply, const QString& authid ) = 0;

  signals:
    void messageOut( const QString& message, const QString& tag = authProviderTag(), MessageLevel level = INFO ) const;

  protected slots:
    void writeDebug( const QString& message, const QString& tag = QString(), MessageLevel level = INFO );

  protected:
    static const QString authProviderTag() { return tr( "Authentication provider" ); }

  private:
    Q_DISABLE_COPY( QgsAuthenticationProvider )

    QgsAuthenticationConfigBase::ProviderType mType;
};

class QgsAuthenticationProviderBasic : public QgsAuthenticationProvider
{
  public:
    QgsAuthenticationProviderBasic( QObject *parent = 0 );

    ~QgsAuthenticationProviderBasic();

    // QgsAuthenticationProvider interface
    void updateNetworkRequest( QNetworkRequest &request, const QString &authid );
    void updateNetworkReply( QNetworkReply *reply, const QString &authid );

  private:
    Q_DISABLE_COPY( QgsAuthenticationProviderBasic )
    static QMap< QString, QPair<QString, QString> > mCredentialCache;
};


#ifndef QT_NO_OPENSSL
/**
 * @class QgsPkiBundle
 * @ingroup core
 * @brief Storage set for constructed SSL certificate, key and optional certificate issuer
 * @since 2.6
 */

class QgsPkiPathsBundle
{
  public:
    QgsPkiPathsBundle( const QgsAuthenticationConfigPkiPaths& config,
                       const QSslCertificate& cert,
                       const QSslKey& certkey,
                       const QSslCertificate& issuer = QSslCertificate() );
    ~QgsPkiPathsBundle();

    bool isValid();

    const QgsAuthenticationConfigPkiPaths config() const { return mConfig; }
    void setConfig( const QgsAuthenticationConfigPkiPaths& config ) { mConfig = config; }

    const QSslCertificate clientCert() const { return mCert; }
    void setClientCert( const QSslCertificate& cert ) { mCert = cert; }

    const QSslKey clientCertKey() const { return mCertKey; }
    void setClientCertKey( const QSslKey& certkey ) { mCertKey = certkey; }

    const QSslCertificate issuerCert() const { return mIssuer; }
    void setIssuerCert( const QSslCertificate& issuer ) { mIssuer = issuer; }

  private:
    QgsAuthenticationConfigPkiPaths mConfig;
    QSslCertificate mCert;
    QSslKey mCertKey;
    QSslCertificate mIssuer;
};


class QgsAuthenticationProviderPkiPaths : public QgsAuthenticationProvider
{
  public:
    QgsAuthenticationProviderPkiPaths( QObject *parent = 0 );

    ~QgsAuthenticationProviderPkiPaths();

    // QgsAuthenticationProvider interface
    void updateNetworkRequest( QNetworkRequest &request, const QString &authid );

    void updateNetworkReply( QNetworkReply *reply, const QString &authid );

  private:
    Q_DISABLE_COPY( QgsAuthenticationProviderPkiPaths )

    QgsPkiPathsBundle * getPkiPathsBundle( const QString &authid );

    void putPkiPathsBundle( const QString &authid, QgsPkiPathsBundle * pkibundle );

    void removePkiPathsBundle( const QString &authid );

    static QMap<QString, QgsPkiPathsBundle *> mPkiPathsBundleCache;
};
#endif

#endif // QGSAUTHENTICATIONPROVIDER_H
