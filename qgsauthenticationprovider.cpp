#include "qgsauthenticationprovider.h"

#include <QFile>
#ifndef QT_NO_OPENSSL
#include <QSslConfiguration>
#include <QSslError>
#endif

#include "qgsauthenticationconfig.h"
#include "qgsauthenticationmanager.h"

void QgsDebugMsg_( const char* msg ) {  qDebug( msg ); }

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

void QgsAuthProviderBasic::updateNetworkRequest( QNetworkRequest& request, const QString& authid )
{
  QgsAuthConfigBasic config = getAuthBasicConfig( authid );
  if ( !config.isValid() )
  {
    QgsDebugMsg_( QString( "Update request config FAILED for authid: %1: basic config invalid" ).arg( authid ).toAscii().constData()  );
    return;
  }

  QString username = config.username();
  QString password = config.password();

  if ( !username.isEmpty() )
  {
    request.setRawHeader( "Authorization", "Basic " + QString( "%1:%2" ).arg( username ).arg( password ).toAscii().toBase64() );
  }
}

void QgsAuthProviderBasic::updateNetworkReply( QNetworkReply *reply, const QString& authid )
{
  Q_UNUSED( reply );
  Q_UNUSED( authid );
}

QgsAuthConfigBasic QgsAuthProviderBasic::getAuthBasicConfig( const QString& authid )
{
  QgsAuthConfigBasic config;

  // check if it is cached
  if ( mAuthBasicCache.contains( authid ) )
  {
    config = mAuthBasicCache.value( authid );
    QgsDebugMsg_( QString( "Retrieved basic bundle for authid %1" ).arg( authid ).toAscii().constData() );
    return config;
  }

  // else build basic bundle
  if ( !QgsAuthManager::instance()->loadAuthenticationConfig( authid, config, true ) )
  {
    QgsDebugMsg_( QString( "Basic bundle for authid %1: FAILED to retrieve config" ).arg( authid ).toAscii().constData() );
    return config;
  }

  // cache bundle
  putAuthBasicConfig( authid, config );

  return config;
}

void QgsAuthProviderBasic::putAuthBasicConfig( const QString& authid, QgsAuthConfigBasic config )
{
  QgsDebugMsg_( QString( "Putting basic config for authid %1" ).arg( authid ).toAscii().constData() );
  mAuthBasicCache.insert( authid, config );
}

void QgsAuthProviderBasic::removeAuthBasicConfig( const QString& authid )
{
  if ( mAuthBasicCache.contains( authid ) )
  {
    mAuthBasicCache.remove( authid );
    QgsDebugMsg_( QString( "Removed basic config for authid: %1" ).arg( authid ).toAscii().constData() );
  }
}

void QgsAuthProviderBasic::clearCachedConfig( const QString& authid )
{
  Q_UNUSED( authid );
}


#ifndef QT_NO_OPENSSL

//////////////////////////////////////////////////////
// QgsPkiBundle
//////////////////////////////////////////////////////

QgsPkiPathsBundle::QgsPkiPathsBundle( const QgsAuthConfigPkiPaths& config,
                                      const QSslCertificate& cert,
                                      const QSslKey& certkey,
                                      const QSslCertificate& issuer )
    : mConfig( config )
    , mCert( cert )
    , mCertKey( certkey )
    , mIssuer( issuer )
{
}

QgsPkiPathsBundle::~QgsPkiPathsBundle()
{
}

bool QgsPkiPathsBundle::isValid()
{
  return ( !mCert.isNull() && !mCertKey.isNull() );
}

//////////////////////////////////////////////////////
// QgsAuthProviderPkiPaths
//////////////////////////////////////////////////////

QMap<QString, QgsPkiPathsBundle *> QgsAuthProviderPkiPaths::mPkiPathsBundleCache = QMap<QString, QgsPkiPathsBundle *>();

QgsAuthProviderPkiPaths::QgsAuthProviderPkiPaths()
    : QgsAuthProvider( QgsAuthType::PkiPaths )
{

}

QgsAuthProviderPkiPaths::~QgsAuthProviderPkiPaths()
{
  qDeleteAll( mPkiPathsBundleCache.values() );
  mPkiPathsBundleCache.clear();
}

void QgsAuthProviderPkiPaths::updateNetworkRequest( QNetworkRequest &request, const QString &authid )
{
  // TODO: is this too restrictive, to intercept only HTTPS connections?
  if ( request.url().scheme().toLower() != QString( "https" ) )
  {
    QgsDebugMsg_( QString( "Update request SSL config SKIPPED for authid %1: not HTTPS" ).arg( authid ).toAscii().constData() );
    return;
  }
  else
  {
    QgsDebugMsg_( QString( "Update request SSL config: HTTPS connection for authid: %1" ).arg( authid ).toAscii().constData() );
  }

  QgsPkiPathsBundle * pkibundle = getPkiPathsBundle( authid );
  if ( !pkibundle || !pkibundle->isValid() )
  {
    QgsDebugMsg_( QString( "Update request SSL config FAILED for authid: %1: PKI bundle invalid" ).arg( authid ).toAscii().constData() );
    return;
  }
  else
  {
    QgsDebugMsg_( QString( "Update request SSL config: PKI bundle valid for authid: %1" ).arg( authid ).toAscii().constData() );
  }

  QSslConfiguration sslConfig = request.sslConfiguration();
  //QSslConfiguration sslConfig( QSslConfiguration::defaultConfiguration() );

  // TODO: test for supported protocols for OpenSSL version built against
  //sslConfig.setProtocol( QSsl::TlsV1SslV3 );

  QSslCertificate issuercert = pkibundle->issuerCert();
  if ( !issuercert.isNull() )
  {
    QList<QSslCertificate> sslCAs( sslConfig.caCertificates() );
    sslCAs << issuercert;
    sslConfig.setCaCertificates( sslCAs );
  }

  sslConfig.setLocalCertificate( pkibundle->clientCert() );
  sslConfig.setPrivateKey( pkibundle->clientCertKey() );

  request.setSslConfiguration( sslConfig );
}

void QgsAuthProviderPkiPaths::updateNetworkReply( QNetworkReply *reply, const QString &authid )
{
  if ( reply->request().url().scheme().toLower() != QString( "https" ) )
  {
    QgsDebugMsg_( QString( "Update reply SSL errors SKIPPED for authid %1: not HTTPS" ).arg( authid ).toAscii().constData() );
    return;
  }
  else
  {
    QgsDebugMsg_( QString( "Update reply SSL errors: HTTPS connection for authid: %1" ).arg( authid ).toAscii().constData() );
  }

  QgsPkiPathsBundle * pkibundle = getPkiPathsBundle( authid );
  if ( !pkibundle || !pkibundle->isValid() )
  {
    QgsDebugMsg_( QString( "Update reply SSL errors FAILED: PKI bundle invalid for authid: %1" ).arg( authid ).toAscii().constData() );
    return;
  }
  else
  {
    QgsDebugMsg_( QString( "Update reply SSL errors: PKI bundle is valid for authid: %1" ).arg( authid ).toAscii().constData() );
  }
  if ( !pkibundle->config().issuerSelfSigned() )
  {
    // TODO: maybe sniff cert to see if it is self-signed, regardless of what user defines
    QgsDebugMsg_( QString( "Update reply SSL errors SKIPPED for authid %1: issuer not self-signed" ).arg( authid ).toAscii().constData() );
    return;
  }

  QList<QSslError> expectedSslErrors;
  QSslError error = QSslError();
  QString issuer = "";
  QSslCertificate issuercert = pkibundle->issuerCert();

  if ( !issuercert.isNull() )
  {
    issuer = "defined issuer";
    error = QSslError( QSslError::SelfSignedCertificate, issuercert );
  }
  else
  {
    // issuer not defined, but may already be in available CAs
    issuer = "ALL in chain";
    error = QSslError( QSslError::SelfSignedCertificate );
  }
  if ( error.error() != QSslError::NoError )
  {
    QgsDebugMsg_( QString( "Adding self-signed cert expected ssl error for %1 for authid: %2" ).arg( issuer ).arg( authid ).toAscii().constData() );
    expectedSslErrors.append( error );
    reply->ignoreSslErrors( expectedSslErrors );
  }
}

void QgsAuthProviderPkiPaths::clearCachedConfig( const QString& authid )
{
  QgsPkiPathsBundle * pkibundle = 0;
  // check if it is cached
  if ( mPkiPathsBundleCache.contains( authid ) )
  {
    pkibundle = mPkiPathsBundleCache.take( authid );
    delete pkibundle;
    pkibundle = 0;
  }
}

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

QgsPkiPathsBundle *QgsAuthProviderPkiPaths::getPkiPathsBundle( const QString& authid )
{
  QgsPkiPathsBundle * bundle = 0;
  bool pem = false; // whether component is from a PEM file

  // check if it is cached
  if ( mPkiPathsBundleCache.contains( authid ) )
  {
    bundle = mPkiPathsBundleCache.value( authid );
    if ( bundle )
    {
      QgsDebugMsg_( QString( "Retrieved PKI bundle for authid %1" ).arg( authid ).toAscii().constData() );
      return bundle;
    }
  }

  // else build PKI bundle
  QgsAuthConfigPkiPaths config;

  if ( !QgsAuthManager::instance()->loadAuthenticationConfig( authid, config, true ) )
  {
    QgsDebugMsg_( QString( "PKI bundle for authid %1: FAILED to retrieve config" ).arg( authid ).toAscii().constData() );
    return bundle;
  }

  // init client cert
  // Note: if this is not valid, no sense continuing
  pem = config.certId().endsWith( ".pem", Qt::CaseInsensitive );
  QSslCertificate clientcert = QSslCertificate( fileData_( config.certId(), pem ), ( pem ? QSsl::Pem : QSsl::Der ) );
  if ( !clientcert.isValid() )
  {
    QgsDebugMsg_( QString( "PKI bundle for authid %1: insert FAILED, client cert is not valid" ).arg( authid ).toAscii().constData() );
    return bundle;
  }

  // init key
  QSslKey clientkey;
  pem = config.keyId().endsWith( ".pem", Qt::CaseInsensitive );
  QByteArray keydata = fileData_( config.keyId(), pem );

  if ( keydata.isNull() )
  {
    QgsDebugMsg_( QString( "PKI bundle for authid %1: insert FAILED, no key data read" ).arg( authid ).toAscii().constData() );
    return bundle;
  }

  if ( !config.keyPassphrase().isNull() )
  {
    clientkey = QSslKey( keydata,
                         ( pem ? pemKeyAlgorithm_( keydata ) : QSsl::Rsa ),
                         ( pem ? QSsl::Pem : QSsl::Der ),
                         QSsl::PrivateKey,
                         config.keyPassphrase().toUtf8() );
  }
  else
  {
    clientkey = QSslKey( keydata,
                         ( pem ? pemKeyAlgorithm_( keydata ) : QSsl::Rsa ),
                         ( pem ? QSsl::Pem : QSsl::Der ) );
  }

  if ( clientkey.isNull() )
  {
    if ( pem )
    {
      QgsDebugMsg_( QString( "PKI bundle for authid %1: insert FAILED, PEM cert key could not be created" ).arg( authid ).toAscii().constData() );
      return bundle;
    }
    else
    {
      // retry DER (binary) with QSsl::Dsa, since its algorithm can not easily be guessed by Qt
      if ( !config.keyPassphrase().isNull() )
      {
        clientkey = QSslKey( keydata, QSsl::Dsa, QSsl::Der, QSsl::PrivateKey, config.keyPassphrase().toUtf8() );
      }
      else
      {
        clientkey = QSslKey( keydata, QSsl::Dsa, QSsl::Der );
      }

      if ( clientkey.isNull() )
      {
        QgsDebugMsg_( QString( "PKI bundle for authid %1: insert FAILED, Der/Dsa cert key could not be created" ).arg( authid ).toAscii().constData() );
        return bundle;
      }
    }
  }

  // init issuer cert
  QSslCertificate issuercert;
  if ( !config.issuerId().isEmpty() )
  {
    pem = config.issuerId().endsWith( ".pem", Qt::CaseInsensitive );
    QByteArray issuerdata = fileData_( config.issuerId(), pem );
    if ( !issuerdata.isNull() )
    {
      issuercert = QSslCertificate( issuerdata, ( pem ? QSsl::Pem : QSsl::Der ) );
      if ( !issuercert.isValid() )
      {
        QgsDebugMsg_( QString( "PKI bundle  for authid %1: insert FAILED, issuer cert is not valid" ).arg( authid ).toAscii().constData() );
        return bundle;
      }
    }
  }

  bundle = new QgsPkiPathsBundle( config, clientcert, clientkey, issuercert );

  // cache bundle
  putPkiPathsBundle( authid, bundle );

  return bundle;
}

void QgsAuthProviderPkiPaths::putPkiPathsBundle( const QString &authid, QgsPkiPathsBundle *pkibundle )
{
  QgsDebugMsg_( QString( "Putting PKI bundle for authid %1" ).arg( authid ).toAscii().constData() );
  mPkiPathsBundleCache.insert( authid, pkibundle );
}

void QgsAuthProviderPkiPaths::removePkiPathsBundle( const QString& authid )
{
  if ( mPkiPathsBundleCache.contains( authid ) )
  {
    QgsPkiPathsBundle * pkibundle = mPkiPathsBundleCache.take( authid );
    delete pkibundle;
    pkibundle = 0;
    QgsDebugMsg_( QString( "Removed PKI bundle for authid: %1" ).arg( authid ).toAscii().constData() );
  }
}

#endif
