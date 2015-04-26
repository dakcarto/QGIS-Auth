/***************************************************************************
    qgsauthenticationprovider.cpp
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

#include "qgsauthenticationprovider.h"

#include <QFile>
#ifndef QT_NO_OPENSSL
#include <QtCrypto>
#include <QSslConfiguration>
#include <QSslError>
#endif

#include "qgsauthenticationconfig.h"
#include "qgsauthenticationmanager.h"
#include "qgslogger.h"

QgsAuthProvider::QgsAuthProvider( QgsAuthType::ProviderType providertype )
    : mType( providertype )
{
}

QgsAuthProvider::~QgsAuthProvider()
{
}

bool QgsAuthProvider::urlToResource( const QString &accessurl, QString *resource, bool withpath )
{
  QString res = QString();
  if ( !accessurl.isEmpty() )
  {
    QUrl url( accessurl );
    if ( url.isValid() )
    {
      res = QString( "%1://%2:%3%4" ).arg( url.scheme() ).arg( url.host() ).arg( url.port() ).arg( withpath ? url.path() : "" );
    }
  }
  *resource = res;
  return ( !res.isEmpty() );
}


//////////////////////////////////////////////////////
// QgsAuthProviderBasic
//////////////////////////////////////////////////////

QMap<QString, QgsAuthConfigBasic> QgsAuthProviderBasic::mAuthBasicCache = QMap<QString, QgsAuthConfigBasic>();

QgsAuthProviderBasic::QgsAuthProviderBasic()
    : QgsAuthProvider( QgsAuthType::Basic )
{
}

QgsAuthProviderBasic::~QgsAuthProviderBasic()
{
  mAuthBasicCache.clear();
}

bool QgsAuthProviderBasic::updateNetworkRequest( QNetworkRequest& request, const QString& authcfg )
{
  QgsAuthConfigBasic config = getAuthBasicConfig( authcfg );
  if ( !config.isValid() )
  {
    QgsDebugMsg( QString( "Update request config FAILED for authcfg: %1: basic config invalid" ).arg( authcfg ) );
    return false;
  }

  QString username = config.username();
  QString password = config.password();

  if ( !username.isEmpty() )
  {
    request.setRawHeader( "Authorization", "Basic " + QString( "%1:%2" ).arg( username ).arg( password ).toAscii().toBase64() );
  }
  return true;
}

bool QgsAuthProviderBasic::updateNetworkReply( QNetworkReply *reply, const QString& authcfg )
{
  Q_UNUSED( reply );
  Q_UNUSED( authcfg );
  return true;
}

QgsAuthConfigBasic QgsAuthProviderBasic::getAuthBasicConfig( const QString& authcfg )
{
  QgsAuthConfigBasic config;

  // check if it is cached
  if ( mAuthBasicCache.contains( authcfg ) )
  {
    config = mAuthBasicCache.value( authcfg );
    QgsDebugMsg( QString( "Retrieved basic bundle for authcfg %1" ).arg( authcfg ) );
    return config;
  }

  // else build basic bundle
  if ( !QgsAuthManager::instance()->loadAuthenticationConfig( authcfg, config, true ) )
  {
    QgsDebugMsg( QString( "Basic bundle for authcfg %1: FAILED to retrieve config" ).arg( authcfg ) );
    return config;
  }

  // cache bundle
  putAuthBasicConfig( authcfg, config );

  return config;
}

void QgsAuthProviderBasic::putAuthBasicConfig( const QString& authcfg, QgsAuthConfigBasic config )
{
  QgsDebugMsg( QString( "Putting basic config for authcfg %1" ).arg( authcfg ) );
  mAuthBasicCache.insert( authcfg, config );
}

void QgsAuthProviderBasic::removeAuthBasicConfig( const QString& authcfg )
{
  if ( mAuthBasicCache.contains( authcfg ) )
  {
    mAuthBasicCache.remove( authcfg );
    QgsDebugMsg( QString( "Removed basic config for authcfg: %1" ).arg( authcfg ) );
  }
}

void QgsAuthProviderBasic::clearCachedConfig( const QString& authcfg )
{
  Q_UNUSED( authcfg );
}


#ifndef QT_NO_OPENSSL

//////////////////////////////////////////////////////
// QgsPkiBundle
//////////////////////////////////////////////////////

QgsPkiBundle::QgsPkiBundle( const QgsAuthConfigPkiPaths& config,
                            const QSslCertificate& cert,
                            const QSslKey& certkey,
                            const QList<QSslCertificate>& cacerts,
                            bool ignoreSeflSigned )
    : mConfig( config )
    , mCert( cert )
    , mCertKey( certkey )
    , mCaCerts( cacerts )
    , mIgnoreSelf( ignoreSeflSigned )
{
}

QgsPkiBundle::~QgsPkiBundle()
{
}

bool QgsPkiBundle::isValid()
{
  return ( !mCert.isNull() && !mCertKey.isNull() );
}

//////////////////////////////////////////////////////
// Local Functions
//////////////////////////////////////////////////////

static QByteArray fileData_( const QString& path, bool astext = false )
{
  QByteArray data;
  QFile file( path );
  if ( file.exists() )
  {
    QFile::OpenMode openflags( QIODevice::ReadOnly );
    if ( astext )
      openflags |= QIODevice::Text;
    bool ret = file.open( openflags );
    if ( ret )
    {
      data = file.readAll();
    }
    file.close();
  }
  return data;
}

QSsl::KeyAlgorithm pemKeyAlgorithm_( const QByteArray& keydata )
{
  QString keytxt( keydata );
  return ( keytxt.contains( "BEGIN DSA P" ) ? QSsl::Dsa : QSsl::Rsa );
}

//////////////////////////////////////////////////////
// QgsAuthProviderPkiPaths
//////////////////////////////////////////////////////

QMap<QString, QgsPkiBundle *> QgsAuthProviderPkiPaths::mPkiBundleCache = QMap<QString, QgsPkiBundle *>();

QgsAuthProviderPkiPaths::QgsAuthProviderPkiPaths()
    : QgsAuthProvider( QgsAuthType::PkiPaths )
{

}

QgsAuthProviderPkiPaths::~QgsAuthProviderPkiPaths()
{
  qDeleteAll( mPkiBundleCache.values() );
  mPkiBundleCache.clear();
}

bool QgsAuthProviderPkiPaths::updateNetworkRequest( QNetworkRequest &request, const QString &authcfg )
{
  // TODO: is this too restrictive, to intercept only HTTPS connections?
  if ( request.url().scheme().toLower() != QString( "https" ) )
  {
    QgsDebugMsg( QString( "Update request SSL config SKIPPED for authcfg %1: not HTTPS" ).arg( authcfg ) );
    return true;
  }

  QgsDebugMsg( QString( "Update request SSL config: HTTPS connection for authcfg: %1" ).arg( authcfg ) );

  QgsPkiBundle * pkibundle = getPkiBundle( authcfg );
  if ( !pkibundle || !pkibundle->isValid() )
  {
    QgsDebugMsg( QString( "Update request SSL config FAILED for authcfg: %1: PKI bundle invalid" ).arg( authcfg ) );
    return false;
  }

  QgsDebugMsg( QString( "Update request SSL config: PKI bundle valid for authcfg: %1" ).arg( authcfg ) );

  QSslConfiguration sslConfig = request.sslConfiguration();
  //QSslConfiguration sslConfig( QSslConfiguration::defaultConfiguration() );

  // TODO: test for supported protocols for OpenSSL version built against
  // IMPORTANT: Qt 4.7 and 4.8 have different protocol enums and default protocols
  //sslConfig.setProtocol( QSsl::TlsV1SslV3 );

  QList<QSslCertificate> cacerts = pkibundle->caCerts();
  if ( !cacerts.isEmpty() )
  {
    QList<QSslCertificate> sslCAs( sslConfig.caCertificates() );
    sslCAs.append( cacerts );
    sslConfig.setCaCertificates( sslCAs );
  }

  sslConfig.setLocalCertificate( pkibundle->clientCert() );
  sslConfig.setPrivateKey( pkibundle->clientCertKey() );

  request.setSslConfiguration( sslConfig );

  return true;
}

bool QgsAuthProviderPkiPaths::updateNetworkReply( QNetworkReply *reply, const QString &authcfg )
{
  if ( reply->request().url().scheme().toLower() != QString( "https" ) )
  {
    QgsDebugMsg( QString( "Update reply SSL errors SKIPPED for authcfg %1: not HTTPS" ).arg( authcfg ) );
    return true;
  }

  QgsDebugMsg( QString( "Update reply SSL errors: HTTPS connection for authcfg: %1" ).arg( authcfg ) );

  QgsPkiBundle * pkibundle = getPkiBundle( authcfg );
  if ( !pkibundle || !pkibundle->isValid() )
  {
    QgsDebugMsg( QString( "Update reply SSL errors FAILED: PKI bundle invalid for authcfg: %1" ).arg( authcfg ) );
    return false;
  }

  QgsDebugMsg( QString( "Update reply SSL errors: PKI bundle is valid for authcfg: %1" ).arg( authcfg ) );

  if ( !pkibundle->ignoreSelfSigned() )
  {
    // TODO: maybe sniff cert to see if it is self-signed, regardless of what user defines
    QgsDebugMsg( QString( "Update reply SSL errors SKIPPED for authcfg %1: CA cert(s) not self-signed" ).arg( authcfg ) );
    return true;
  }

  QList<QSslError> errors;
  QString cacert = "";
  QList<QSslCertificate> cacerts = pkibundle->caCerts();

  if ( !cacerts.isEmpty() )
  {
    cacert = "defined CA cert(s)";
    Q_FOREACH ( const QSslCertificate& cert, cacerts )
    {
      errors.append( QSslError( QSslError::SelfSignedCertificate, cert ) );
    }
  }
  else
  {
    // CA cert(s) not defined, but may already be in available CAs
    cacert = "ALL in chain";
    errors.append( QSslError( QSslError::SelfSignedCertificate ) );
  }
  if ( !errors.isEmpty() )
  {
    QgsDebugMsg( QString( "Adding self-signed cert expected ssl error for %1 for authcfg: %2" ).arg( cacert ).arg( authcfg ) );
    reply->ignoreSslErrors( errors );
  }
  return true;
}

void QgsAuthProviderPkiPaths::clearCachedConfig( const QString& authcfg )
{
  QgsPkiBundle * pkibundle = 0;
  // check if it is cached
  if ( mPkiBundleCache.contains( authcfg ) )
  {
    pkibundle = mPkiBundleCache.take( authcfg );
    delete pkibundle;
    pkibundle = 0;
  }
}

// static
const QByteArray QgsAuthProviderPkiPaths::certAsPem( const QString &certpath )
{
  bool pem = certpath.endsWith( ".pem", Qt::CaseInsensitive );
  if ( pem )
  {
    return fileData_( certpath, pem );
  }
  QSslCertificate clientcert( fileData_( certpath ), QSsl::Der );
  return ( !clientcert.isNull() ? clientcert.toPem() : QByteArray() );
}

// static
const QByteArray QgsAuthProviderPkiPaths::keyAsPem( const QString &keypath,
    const QString &keypass,
    QString *algtype,
    bool reencrypt )
{
  bool pem = keypath.endsWith( ".pem", Qt::CaseInsensitive );
  QByteArray keydata( fileData_( keypath, pem ) );

  QSslKey clientkey;
  clientkey = QSslKey( keydata,
                       QSsl::Rsa,
                       pem ? QSsl::Pem : QSsl::Der,
                       QSsl::PrivateKey,
                       !keypass.isEmpty() ? keypass.toUtf8() : QByteArray() );
  if ( clientkey.isNull() )
  {
    // try DSA algorithm, since Qt can't seem to determine it otherwise
    clientkey = QSslKey( keydata,
                         QSsl::Dsa,
                         pem ? QSsl::Pem : QSsl::Der,
                         QSsl::PrivateKey,
                         !keypass.isEmpty() ? keypass.toUtf8() : QByteArray() );
    if ( clientkey.isNull() )
    {
      return QByteArray();
    }
    if ( algtype )
      *algtype = "dsa";
  }
  else
  {
    if ( algtype )
      *algtype = "rsa";
  }

  // reapply passphrase if protection is requested and passphrase exists
  return ( clientkey.toPem( reencrypt && !keypass.isEmpty() ? keypass.toUtf8() : QByteArray() ) );
}

// static
const QList<QSslCertificate> QgsAuthProviderPkiPaths::caCerts( const QString& cacertspath )
{
  QList<QSslCertificate> cacerts;
  bool pem = cacertspath.endsWith( ".pem", Qt::CaseInsensitive );
  cacerts = QSslCertificate::fromData( fileData_( cacertspath, pem ), pem ? QSsl::Pem : QSsl::Der );
  if ( cacerts.isEmpty() )
  {
    QgsDebugMsg( QString( "Parsed CA cert(s) EMPTY for: %1" ).arg( cacertspath ) );
  }
  return cacerts;
}

// static
const QByteArray QgsAuthProviderPkiPaths::caCertsAsPem( const QString& cacertspath )
{
  QByteArray capem;
  QList<QSslCertificate> cacerts( QgsAuthProviderPkiPaths::caCerts( cacertspath ) );
  if ( !cacerts.isEmpty() )
  {
    QStringList cacertslist;
    Q_FOREACH ( const QSslCertificate& cert, cacerts )
    {
      cacertslist << cert.toPem();
    }
    capem = cacertslist.join( "\n" ).toAscii() + "\n";
  }
  return capem;
}


QgsPkiBundle *QgsAuthProviderPkiPaths::getPkiBundle( const QString& authcfg )
{
  QgsPkiBundle * bundle = 0;

  // check if it is cached
  if ( mPkiBundleCache.contains( authcfg ) )
  {
    bundle = mPkiBundleCache.value( authcfg );
    if ( bundle )
    {
      QgsDebugMsg( QString( "Retrieved PKI bundle for authcfg %1" ).arg( authcfg ) );
      return bundle;
    }
  }

  // else build PKI bundle
  QgsAuthConfigPkiPaths config;

  if ( !QgsAuthManager::instance()->loadAuthenticationConfig( authcfg, config, true ) )
  {
    QgsDebugMsg( QString( "PKI bundle for authcfg %1: FAILED to retrieve config" ).arg( authcfg ) );
    return bundle;
  }

  // init client cert
  // Note: if this is not valid, no sense continuing
  QSslCertificate clientcert( QgsAuthProviderPkiPaths::certAsPem( config.certId() ) );
  if ( !clientcert.isValid() )
  {
    QgsDebugMsg( QString( "PKI bundle for authcfg %1: insert FAILED, client cert is not valid" ).arg( authcfg ) );
    return bundle;
  }

  // init key
  QString algtype;
  QByteArray keydata( QgsAuthProviderPkiPaths::keyAsPem( config.keyId(), config.keyPassphrase(), &algtype ) );

  if ( keydata.isNull() )
  {
    QgsDebugMsg( QString( "PKI bundle for authcfg %1: insert FAILED, no key data read" ).arg( authcfg ) );
    return bundle;
  }

  QSslKey clientkey( keydata,
                     ( algtype == "rsa" ) ? QSsl::Rsa : QSsl::Dsa,
                     QSsl::Pem,
                     QSsl::PrivateKey,
                     !config.keyPassphrase().isEmpty() ? config.keyPassphrase().toUtf8() : QByteArray() );

  if ( clientkey.isNull() )
  {
    QgsDebugMsg( QString( "PKI bundle for authcfg %1: insert FAILED, PEM cert key could not be created" ).arg( authcfg ) );
    return bundle;
  }

  // init CA cert(s)
  QList<QSslCertificate> cacerts;
  if ( !config.caCertsId().isEmpty() )
  {
    cacerts = QgsAuthProviderPkiPaths::caCerts( config.caCertsId() );
    Q_FOREACH ( const QSslCertificate& cert, cacerts )
    {
      if ( !cert.isValid() )
      {
        QgsDebugMsg( QString( "PKI bundle for authcfg %1: insert FAILED, a CA cert is not valid" ).arg( authcfg ) );
        return bundle;
      }
    }
  }

  bundle = new QgsPkiBundle( config, clientcert, clientkey, cacerts, config.ignoreSelfSigned() );

  // cache bundle
  putPkiBundle( authcfg, bundle );

  return bundle;
}

void QgsAuthProviderPkiPaths::putPkiBundle( const QString &authcfg, QgsPkiBundle *pkibundle )
{
  QgsDebugMsg( QString( "Putting PKI bundle for authcfg %1" ).arg( authcfg ) );
  mPkiBundleCache.insert( authcfg, pkibundle );
}

void QgsAuthProviderPkiPaths::removePkiBundle( const QString& authcfg )
{
  if ( mPkiBundleCache.contains( authcfg ) )
  {
    QgsPkiBundle * pkibundle = mPkiBundleCache.take( authcfg );
    delete pkibundle;
    pkibundle = 0;
    QgsDebugMsg( QString( "Removed PKI bundle for authcfg: %1" ).arg( authcfg ) );
  }
}

//////////////////////////////////////////////////////
// QgsAuthProviderPkiPkcs12
//////////////////////////////////////////////////////

QMap<QString, QgsPkiBundle *> QgsAuthProviderPkiPkcs12::mPkiBundleCache = QMap<QString, QgsPkiBundle *>();

QgsAuthProviderPkiPkcs12::QgsAuthProviderPkiPkcs12()
    : QgsAuthProviderPkiPaths()
{
  setProviderType( QgsAuthType::PkiPkcs12 );
}

QgsAuthProviderPkiPkcs12::~QgsAuthProviderPkiPkcs12()
{
}

QCA::KeyBundle keyBundle_( const QString &path, const QString &pass )
{
  QCA::SecureArray passarray;
  if ( !pass.isEmpty() )
    passarray = QCA::SecureArray( pass.toUtf8() );
  QCA::ConvertResult res;
  QCA::KeyBundle bundle( QCA::KeyBundle::fromFile( path, passarray, &res, QString( "qca-ossl" ) ) );
  return ( res == QCA::ConvertGood ? bundle : QCA::KeyBundle() );
}

// static
const QString QgsAuthProviderPkiPkcs12::certAsPem( const QString &bundlepath, const QString &bundlepass )
{
  QString cert;
  if ( !QCA::isSupported( "pkcs12" ) )
    return cert;

  QCA::KeyBundle bundle( keyBundle_( bundlepath, bundlepass ) );
  if ( bundle.isNull() )
    return cert;

  return bundle.certificateChain().primary().toPEM();
}

// static
const QString QgsAuthProviderPkiPkcs12::keyAsPem( const QString &bundlepath, const QString &bundlepass, bool reencrypt )
{
  QString key;
  if ( !QCA::isSupported( "pkcs12" ) )
    return key;

  QCA::KeyBundle bundle( keyBundle_( bundlepath, bundlepass ) );
  if ( bundle.isNull() )
    return key;

  QCA::SecureArray passarray;
  if ( reencrypt && !bundlepass.isEmpty() )
    passarray = QCA::SecureArray( bundlepass.toUtf8() );

  return bundle.privateKey().toPEM( passarray );
}

// static
const QString QgsAuthProviderPkiPkcs12::caCertsAsPem( const QString &bundlepath,
    const QString &bundlepass,
    const QString &cacertspath )
{
  // interim fix until block below is corrected
  // same as QgsAuthProviderPkiPaths::caCertsAsPem, but returns QString
  Q_UNUSED( bundlepath );
  Q_UNUSED( bundlepass );

  return QString( QgsAuthProviderPkiPaths::certAsPem( cacertspath ) );

  //FIXME: can return empty result if resolution of chain has issues;
  //       needs updated
#if 0
  QString cacertspem;
  if ( !QCA::isSupported( "pkcs12" ) )
    return cacertspem;

  QCA::KeyBundle bundle( keyBundle_( bundlepath, bundlepass ) );
  if ( bundle.isNull() )
    return cacertspem;

  QList<QCA::Certificate> calist;
  if ( !cacertspath.isEmpty() && QFile::exists( cacertspath ) )
  {
    bool pem = cacertspath.endsWith( ".pem", Qt::CaseInsensitive );
    QCA::ConvertResult res;
    QCA::Certificate cacert;
    if ( pem )
    {
      cacert = QCA::Certificate::fromPEM( QString( fileData_( cacertspath, pem ) ), &res, QString( "qca-ossl" ) );
    }
    else
    {
      cacert = QCA::Certificate::fromDER( fileData_( cacertspath, pem ), &res, QString( "qca-ossl" ) );
    }
    // TODO: is testing against primary() necessary, or can we just always add it to calist?
    //       should this just be part of GUI validation?
    if ( res == QCA::ConvertGood
         && !cacert.isNull()
         && cacert.isIssuerOf( bundle.certificateChain().primary() ) )
    {
      calist << cacert;
    }
  }

  if ( QCA::haveSystemStore() )
    calist += QCA::systemStore().certificates();

  QCA::Validity valid;
  QCA::CertificateChain fullchain( bundle.certificateChain().complete( calist, &valid ) );

  if ( valid != QCA::ValidityGood || fullchain.isEmpty() )
  {
    // TODO: add debug output
    return cacertspem;
  }

  QStringList chainlist;
  foreach ( QCA::Certificate cert, fullchain )
  {
    if ( cert == bundle.certificateChain().primary() )
      continue; // skip non-issuer-chain cert

    chainlist << cert.toPEM();
  }

  return chainlist.join( "\n" );
#endif
}

QgsPkiBundle *QgsAuthProviderPkiPkcs12::getPkiBundle( const QString &authcfg )
{
  QgsPkiBundle * bundle = 0;

  // check if it is cached
  if ( mPkiBundleCache.contains( authcfg ) )
  {
    bundle = mPkiBundleCache.value( authcfg );
    if ( bundle )
    {
      QgsDebugMsg( QString( "Retrieved PKI bundle for authcfg %1" ).arg( authcfg ) );
      return bundle;
    }
  }

  // else build PKI bundle
  QgsAuthConfigPkiPkcs12 config;

  if ( !QgsAuthManager::instance()->loadAuthenticationConfig( authcfg, config, true ) )
  {
    QgsDebugMsg( QString( "PKI bundle for authcfg %1: FAILED to retrieve config" ).arg( authcfg ) );
    return bundle;
  }

  // init client cert
  // Note: if this is not valid, no sense continuing
  QSslCertificate clientcert( QgsAuthProviderPkiPkcs12::certAsPem( config.bundlePath(), config.bundlePassphrase() ).toAscii() );
  if ( !clientcert.isValid() )
  {
    QgsDebugMsg( QString( "PKI bundle for authcfg %1: insert FAILED, client cert is not valid" ).arg( authcfg ) );
    return bundle;
  }

  // init key
  QByteArray keydata( QgsAuthProviderPkiPkcs12::keyAsPem( config.bundlePath(), config.bundlePassphrase() ).toAscii() );

  if ( keydata.isNull() )
  {
    QgsDebugMsg( QString( "PKI bundle for authcfg %1: insert FAILED, no key data read" ).arg( authcfg ) );
    return bundle;
  }

  QSslKey clientkey( keydata,
                     QSsl::Rsa,
                     QSsl::Pem,
                     QSsl::PrivateKey,
                     !config.bundlePassphrase().isNull() ? config.bundlePassphrase().toUtf8() : QByteArray() );

  // init CA cert(s)
  QList<QSslCertificate> cacerts;
  if ( !config.caCertsPath().isEmpty() )
  {
    cacerts = QgsAuthProviderPkiPaths::caCerts( config.caCertsPath() );
    Q_FOREACH ( const QSslCertificate& cert, cacerts )
    {
      if ( !cert.isValid() )
      {
        QgsDebugMsg( QString( "PKI bundle for authcfg %1: insert FAILED, a CA cert is not valid" ).arg( authcfg ) );
        return bundle;
      }
    }
  }

  bundle = new QgsPkiBundle( config, clientcert, clientkey, cacerts, config.ignoreSelfSigned() );

  // cache bundle
  putPkiBundle( authcfg, bundle );

  return bundle;

}

#endif