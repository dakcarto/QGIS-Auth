/***************************************************************************
    qgsauthenticationprovider.h
    ---------------------
    begin                : October 5, 2014
    copyright            : (C) 2014 by Boundless Spatial, Inc. USA
    author               : Larry Shaffer
    email                : lshaffer at boundlessgeo dot com
 ***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

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

/** \ingroup core
 * \brief Base authentication provider class (not meant to be directly used)
 * \since 2.8
 */
class CORE_EXPORT QgsAuthProvider
{

  public:

    explicit QgsAuthProvider( QgsAuthType::ProviderType providertype = QgsAuthType::None );

    virtual ~QgsAuthProvider();

    QgsAuthType::ProviderType providerType() const { return mType; }
    void setProviderType( QgsAuthType::ProviderType ptype ) { mType = ptype; }

    static bool urlToResource( const QString& accessurl, QString *resource, bool withpath = false );

    virtual bool updateNetworkRequest( QNetworkRequest &request, const QString& authcfg ) = 0;

    virtual bool updateNetworkReply( QNetworkReply *reply, const QString& authcfg ) = 0;

    virtual void clearCachedConfig( const QString& authcfg ) = 0;

  protected:
    static const QString authProviderTag() { return QObject::tr( "Authentication provider" ); }

  private:
    QgsAuthType::ProviderType mType;
};

/** \ingroup core
 * \brief Basic username/password authentication provider class
 * \since 2.8
 */
class CORE_EXPORT QgsAuthProviderBasic : public QgsAuthProvider
{
  public:
    QgsAuthProviderBasic();

    ~QgsAuthProviderBasic();

    // QgsAuthProvider interface
    bool updateNetworkRequest( QNetworkRequest &request, const QString &authcfg );
    bool updateNetworkReply( QNetworkReply *reply, const QString &authcfg );
    void clearCachedConfig( const QString& authcfg );

  private:

    QgsAuthConfigBasic getAuthBasicConfig( const QString& authcfg );

    void putAuthBasicConfig( const QString& authcfg, QgsAuthConfigBasic config );

    void removeAuthBasicConfig( const QString& authcfg );

    static QMap<QString, QgsAuthConfigBasic> mAuthBasicCache;
};


#ifndef QT_NO_OPENSSL
/** \ingroup core
 * \brief Storage set for constructed SSL certificate, key and optional CA certificates
 * \since 2.6
 */
class CORE_EXPORT QgsPkiBundle
{
  public:
    QgsPkiBundle( const QgsAuthConfigPkiPaths& config,
                  const QSslCertificate& cert,
                  const QSslKey& certkey );
    ~QgsPkiBundle();

    bool isValid();

    const QgsAuthConfigPkiPaths config() const { return mConfig; }
    void setConfig( const QgsAuthConfigPkiPaths& config ) { mConfig = config; }

    const QSslCertificate clientCert() const { return mCert; }
    void setClientCert( const QSslCertificate& cert ) { mCert = cert; }

    const QSslKey clientCertKey() const { return mCertKey; }
    void setClientCertKey( const QSslKey& certkey ) { mCertKey = certkey; }

  private:
    QgsAuthConfigBase mConfig;
    QSslCertificate mCert;
    QSslKey mCertKey;
};

/** \ingroup core
 * \brief PKI (PEM/DER paths only) authentication provider class
 * \since 2.8
 */
class CORE_EXPORT QgsAuthProviderPkiPaths : public QgsAuthProvider
{
  public:
    QgsAuthProviderPkiPaths();

    virtual ~QgsAuthProviderPkiPaths();

    // QgsAuthProvider interface
    bool updateNetworkRequest( QNetworkRequest &request, const QString &authcfg );
    bool updateNetworkReply( QNetworkReply *reply, const QString &authcfg );
    void clearCachedConfig( const QString& authcfg );

    static const QByteArray certAsPem( const QString &certpath );

    static const QByteArray keyAsPem( const QString &keypath,
                                      const QString &keypass = QString(),
                                      QString *algtype = 0,
                                      bool reencrypt = true );

  protected:

    virtual QgsPkiBundle * getPkiBundle( const QString &authcfg );

    virtual void putPkiBundle( const QString &authcfg, QgsPkiBundle * pkibundle );

    virtual void removePkiBundle( const QString &authcfg );

  private:

    static QMap<QString, QgsPkiBundle *> mPkiBundleCache;
};

/** \ingroup core
 * \brief PKI (.p12/.pfx and CA paths only) authentication provider class
 * \note Since this uses QCA's PKCS#12 support, signing CAs in the user's root OS cert store will also be queried.
 * \since 2.8
 */
class CORE_EXPORT QgsAuthProviderPkiPkcs12 : public QgsAuthProviderPkiPaths
{
  public:
    QgsAuthProviderPkiPkcs12();

    ~QgsAuthProviderPkiPkcs12();

    static const QString certAsPem( const QString &bundlepath, const QString &bundlepass );

    static const QString keyAsPem( const QString &bundlepath, const QString &bundlepass, bool reencrypt = true );

  protected:

    QgsPkiBundle * getPkiBundle( const QString &authcfg );

  private:

    static QMap<QString, QgsPkiBundle *> mPkiBundleCache;
};

/** \ingroup core
 * \brief Identity certificate authentication provider class
 * \since 2.8
 */
class CORE_EXPORT QgsAuthProviderIdentityCert : public QgsAuthProvider
{
  public:
    QgsAuthProviderIdentityCert();

    virtual ~QgsAuthProviderIdentityCert();

    // QgsAuthProvider interface
    bool updateNetworkRequest( QNetworkRequest &request, const QString &authcfg );
    bool updateNetworkReply( QNetworkReply *reply, const QString &authcfg );
    void clearCachedConfig( const QString& authcfg );

    static const QByteArray certAsPem( const QString &certid );

    static const QByteArray keyAsPem( const QString &certid,
                                      const QString &keypass = QString(),
                                      bool reencrypt = true );

  protected:

    virtual QgsPkiBundle * getPkiBundle( const QString &authcfg );

    virtual void putPkiBundle( const QString &authcfg, QgsPkiBundle * pkibundle );

    virtual void removePkiBundle( const QString &authcfg );

  private:

    static QMap<QString, QgsPkiBundle *> mPkiBundleCache;
};

#endif

#endif // QGSAUTHENTICATIONPROVIDER_H
