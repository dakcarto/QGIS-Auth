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

    void QgsDebugMsg( const char* msg ) {  qDebug( msg ); }

    QgsAuthType::ProviderType providerType() const { return mType; }
    void setProviderType( QgsAuthType::ProviderType ptype ) { mType = ptype; }

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

class QgsPkiBundle
{
  public:
    QgsPkiBundle( const QgsAuthConfigPkiPaths& config,
                  const QSslCertificate& cert,
                  const QSslKey& certkey,
                  const QSslCertificate& issuer = QSslCertificate(),
                  bool issuerSeflSigned = false );
    ~QgsPkiBundle();

    bool isValid();

    const QgsAuthConfigPkiPaths config() const { return mConfig; }
    void setConfig( const QgsAuthConfigPkiPaths& config ) { mConfig = config; }

    const QSslCertificate clientCert() const { return mCert; }
    void setClientCert( const QSslCertificate& cert ) { mCert = cert; }

    const QSslKey clientCertKey() const { return mCertKey; }
    void setClientCertKey( const QSslKey& certkey ) { mCertKey = certkey; }

    const QSslCertificate issuerCert() const { return mIssuer; }
    void setIssuerCert( const QSslCertificate& issuer ) { mIssuer = issuer; }

    bool issuerSelfSigned() const { return mIssuerSelf; }
    void setIssuerSelfSigned( bool selfsigned ) { mIssuerSelf = selfsigned; }

  private:
    QgsAuthConfigBase mConfig;
    QSslCertificate mCert;
    QSslKey mCertKey;
    QSslCertificate mIssuer;
    bool mIssuerSelf;
};


class QgsAuthProviderPkiPaths : public QgsAuthProvider
{
  public:
    QgsAuthProviderPkiPaths();

    virtual ~QgsAuthProviderPkiPaths();

    // QgsAuthProvider interface
    void updateNetworkRequest( QNetworkRequest &request, const QString &authid );
    void updateNetworkReply( QNetworkReply *reply, const QString &authid );
    void clearCachedConfig( const QString& authid );

    static const QByteArray certAsPem( const QString &certpath );

    static const QByteArray keyAsPem( const QString &keypath,
                                      const QString &keypass = QString(),
                                      QString *algtype = 0,
                                      bool reencrypt = true );

    static const QByteArray issuerAsPem( const QString &issuerpath );

  protected:

    virtual QgsPkiBundle * getPkiBundle( const QString &authid );

    virtual void putPkiBundle( const QString &authid, QgsPkiBundle * pkibundle );

    virtual void removePkiBundle( const QString &authid );

  private:

    static QMap<QString, QgsPkiBundle *> mPkiBundleCache;
};

class QgsAuthProviderPkiPkcs12 : public QgsAuthProviderPkiPaths
{
  public:
    QgsAuthProviderPkiPkcs12();

    ~QgsAuthProviderPkiPkcs12();

    static const QString certAsPem( const QString &bundlepath, const QString &bundlepass );

    static const QString keyAsPem( const QString &bundlepath, const QString &bundlepass, bool reencrypt = true );

    static const QString issuerAsPem( const QString &bundlepath, const QString &bundlepass, const QString &issuerpath );

  protected:

    QgsPkiBundle * getPkiBundle( const QString &authid );

  private:

    static QMap<QString, QgsPkiBundle *> mPkiBundleCache;
};
#endif

#endif // QGSAUTHENTICATIONPROVIDER_H
