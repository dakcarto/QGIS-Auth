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

class QgsAuthProvider
{

  public:

    explicit QgsAuthProvider( QgsAuthType::ProviderType providertype = QgsAuthType::None );

    virtual ~QgsAuthProvider();

    QgsAuthType::ProviderType providerType() const { return mType; }

    static bool urlToResource( const QString& accessurl, QString *resource, bool withpath = false );

    virtual void updateNetworkRequest( QNetworkRequest &request, const QString& authid ) = 0;

    virtual void updateNetworkReply( QNetworkReply *reply, const QString& authid ) = 0;

    virtual void clearCachedConfig( const QString& authid ) = 0;

  protected:
    static const QString authProviderTag() { return QObject::tr( "Authentication provider" ); }

  private:
    QgsAuthType::ProviderType mType;
};


class QgsAuthProviderBasic : public QgsAuthProvider
{
  public:
    QgsAuthProviderBasic();

    ~QgsAuthProviderBasic();

    // QgsAuthProvider interface
    void updateNetworkRequest( QNetworkRequest &request, const QString &authid );
    void updateNetworkReply( QNetworkReply *reply, const QString &authid );
    void clearCachedConfig( const QString& authid );

  private:

    QgsAuthConfigBasic getAuthBasicConfig( const QString& authid );

    void putAuthBasicConfig( const QString& authid, QgsAuthConfigBasic config );

    void removeAuthBasicConfig( const QString& authid );

    static QMap<QString, QgsAuthConfigBasic> mAuthBasicCache;
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
    QgsPkiPathsBundle( const QgsAuthConfigPkiPaths& config,
                       const QSslCertificate& cert,
                       const QSslKey& certkey,
                       const QSslCertificate& issuer = QSslCertificate() );
    ~QgsPkiPathsBundle();

    bool isValid();

    const QgsAuthConfigPkiPaths config() const { return mConfig; }
    void setConfig( const QgsAuthConfigPkiPaths& config ) { mConfig = config; }

    const QSslCertificate clientCert() const { return mCert; }
    void setClientCert( const QSslCertificate& cert ) { mCert = cert; }

    const QSslKey clientCertKey() const { return mCertKey; }
    void setClientCertKey( const QSslKey& certkey ) { mCertKey = certkey; }

    const QSslCertificate issuerCert() const { return mIssuer; }
    void setIssuerCert( const QSslCertificate& issuer ) { mIssuer = issuer; }

  private:
    QgsAuthConfigPkiPaths mConfig;
    QSslCertificate mCert;
    QSslKey mCertKey;
    QSslCertificate mIssuer;
};


class QgsAuthProviderPkiPaths : public QgsAuthProvider
{
  public:
    QgsAuthProviderPkiPaths();

    ~QgsAuthProviderPkiPaths();

    // QgsAuthProvider interface
    void updateNetworkRequest( QNetworkRequest &request, const QString &authid );
    void updateNetworkReply( QNetworkReply *reply, const QString &authid );
    void clearCachedConfig( const QString& authid );

  private:

    QgsPkiPathsBundle * getPkiPathsBundle( const QString &authid );

    void putPkiPathsBundle( const QString &authid, QgsPkiPathsBundle * pkibundle );

    void removePkiPathsBundle( const QString &authid );

    static QMap<QString, QgsPkiPathsBundle *> mPkiPathsBundleCache;
};
#endif

#endif // QGSAUTHENTICATIONPROVIDER_H
