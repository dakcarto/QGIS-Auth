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

class QgsAuthProvider : public QObject
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

    explicit QgsAuthProvider( QObject *parent = 0 ,
                              QgsAuthType::ProviderType providertype = QgsAuthType::None );

    virtual ~QgsAuthProvider();

    QgsAuthType::ProviderType providerType() const { return mType; }

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
    Q_DISABLE_COPY( QgsAuthProvider )

    QgsAuthType::ProviderType mType;
};

class QgsAuthProviderBasic : public QgsAuthProvider
{
  public:
    QgsAuthProviderBasic( QObject *parent = 0 );

    ~QgsAuthProviderBasic();

    // QgsAuthProvider interface
    void updateNetworkRequest( QNetworkRequest &request, const QString &authid );
    void updateNetworkReply( QNetworkReply *reply, const QString &authid );

  private:
    Q_DISABLE_COPY( QgsAuthProviderBasic )
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
    QgsAuthProviderPkiPaths( QObject *parent = 0 );

    ~QgsAuthProviderPkiPaths();

    // QgsAuthProvider interface
    void updateNetworkRequest( QNetworkRequest &request, const QString &authid );

    void updateNetworkReply( QNetworkReply *reply, const QString &authid );

  private:
    Q_DISABLE_COPY( QgsAuthProviderPkiPaths )

    QgsPkiPathsBundle * getPkiPathsBundle( const QString &authid );

    void putPkiPathsBundle( const QString &authid, QgsPkiPathsBundle * pkibundle );

    void removePkiPathsBundle( const QString &authid );

    static QMap<QString, QgsPkiPathsBundle *> mPkiPathsBundleCache;
};
#endif

#endif // QGSAUTHENTICATIONPROVIDER_H
