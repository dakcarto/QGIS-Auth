#include "qgsauthenticationprovider.h"

#include <QFile>
#ifndef QT_NO_OPENSSL
#include <QSslConfiguration>
#include <QSslError>
#endif

#include "qgsauthenticationconfig.h"
#include "qgsauthenticationmanager.h"

QgsAuthProvider::QgsAuthProvider( QObject *parent, QgsAuthType::ProviderType providertype )
    : QObject( parent )
    , mType( providertype )
{
  connect( this, SIGNAL( messageOut( const QString&, const QString&, MessageLevel ) ),
           this, SLOT( writeDebug( const QString&, const QString&, MessageLevel ) ) );
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

void QgsAuthProvider::writeDebug( const QString &message, const QString &tag, MessageLevel level )
{
  Q_UNUSED( tag );

  QString msg;
  switch ( level )
  {
    case INFO:
      break;
    case WARNING:
      msg += "WARNING: ";
      break;
    case CRITICAL:
      msg += "ERROR: ";
      break;
    default:
      break;
  }

  msg += message;
  qDebug( "%s", msg.toLatin1().constData() );
}


//////////////////////////////////////////////////////
// QgsAuthProviderBasic
//////////////////////////////////////////////////////

QgsAuthProviderBasic::QgsAuthProviderBasic( QObject *parent )
    : QgsAuthProvider( parent, QgsAuthType::Basic )
{
}

QgsAuthProviderBasic::~QgsAuthProviderBasic()
{
}

void QgsAuthProviderBasic::updateNetworkRequest( QNetworkRequest &request, const QString &authid )
{
  Q_UNUSED( request );
  Q_UNUSED( authid );
}

void QgsAuthProviderBasic::updateNetworkReply( QNetworkReply *reply, const QString &authid )
{
  Q_UNUSED( reply );
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

QgsAuthProviderPkiPaths::QgsAuthProviderPkiPaths( QObject *parent )
    : QgsAuthProvider( parent, QgsAuthType::PkiPaths )
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
    emit messageOut( QString( "Update request SSL config SKIPPED for authid %1: "
                              "not HTTPS" ).arg( authid ) );
    return;
  }
  else
  {
    emit messageOut( QString( "Update request SSL config: "
                              "HTTPS connection for authid: %1" ).arg( authid ) );
  }

  QgsPkiPathsBundle * pkibundle = getPkiPathsBundle( authid );
  if ( !pkibundle || !pkibundle->isValid() )
  {
    emit messageOut( QString( "Update request SSL config FAILED for authid: %1: "
                              "PKI bundle invalid" ).arg( authid ),
                     authProviderTag(), CRITICAL );
    return;
  }
  else
  {
    emit messageOut( QString( "Update request SSL config: "
                              "PKI bundle valid for authid: %1" ).arg( authid ) );
  }

  QSslConfiguration sslConfig = request.sslConfiguration();
  //QSslConfiguration sslConfig( QSslConfiguration::defaultConfiguration() );

  sslConfig.setProtocol( QSsl::TlsV1SslV3 );

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
    emit messageOut( QString( "Update reply SSL errors SKIPPED for authid %1: "
                              "not HTTPS" ).arg( authid ) );
    return;
  }
  else
  {
    emit messageOut( QString( "Update reply SSL errors: "
                              "HTTPS connection for authid: %1" ).arg( authid ) );
  }

  QgsPkiPathsBundle * pkibundle = getPkiPathsBundle( authid );
  if ( !pkibundle || !pkibundle->isValid() )
  {
    emit messageOut( QString( "Update reply SSL errors FAILED: "
                              "PKI bundle invalid for authid: %1" ).arg( authid ),
                     authProviderTag(), CRITICAL );
    return;
  }
  else
  {
    emit messageOut( QString( "Update reply SSL errors: "
                              "PKI bundle is valid for authid: %1" ).arg( authid ) );
  }
  if ( !pkibundle->config().issuerSelfSigned() )
  {
    // TODO: maybe sniff cert to see if it is self-signed, regardless of what user defines
    emit messageOut( QString( "Update reply SSL errors SKIPPED for authid %1: "
                              "PKI issuer not set as self-signed" ).arg( authid ) );
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
    emit messageOut( QString( "Adding self-signed cert expected ssl error "
                              "for %1 for authid: %2" ).arg( issuer ).arg( authid ) );
    expectedSslErrors.append( error );
    reply->ignoreSslErrors( expectedSslErrors );
  }
}

static QByteArray fileData_( const QString& path )
{
  QByteArray data;
  QFile file( path );
  if ( file.exists() )
  {
    bool ret = file.open( QIODevice::ReadOnly | QIODevice::Text );
    if ( ret )
    {
      data = file.readAll();
    }
    file.close();
  }
  return data;
}

QSsl::KeyAlgorithm keyAlgorithm_( const QByteArray& keydata )
{
  QString keytxt( keydata );
  return (( keytxt.contains( "BEGIN DSA P" ) ) ? QSsl::Dsa : QSsl::Rsa );
}

QgsPkiPathsBundle *QgsAuthProviderPkiPaths::getPkiPathsBundle( const QString& authid )
{
  QgsPkiPathsBundle * pkibundle = 0;

  // check if it is cached
  if ( mPkiPathsBundleCache.contains( authid ) )
  {
    pkibundle = mPkiPathsBundleCache.value( authid );
    if ( pkibundle )
    {
      emit messageOut( QString( "Retrieved PKI bundle for authid %1" ).arg( authid ) );
      return pkibundle;
    }
  }

  // else build PKI bundle
  QgsAuthConfigPkiPaths pkiconfig;

  if ( !QgsAuthManager::instance()->loadAuthenticationConfig( authid, pkiconfig, true ) )
  {
    emit messageOut( QString( "PKI bundle for authid %1: "
                              "FAILED to retrieve config" ).arg( authid ),
                     authProviderTag(), CRITICAL );
    return pkibundle;
  }

  // init client cert
  // Note: if this is not valid, no sense continuing
  QSslCertificate clientcert = QSslCertificate( fileData_( pkiconfig.certId() ) );
  if ( !clientcert.isValid() )
  {
    emit messageOut( QString( "PKI bundle for authid %1: "
                              "insert FAILED, client cert is not valid" ).arg( authid ),
                     authProviderTag(), CRITICAL );
    return pkibundle;
  }

  // init key
  QSslKey clientkey;
  QByteArray keydata = fileData_( pkiconfig.keyId() );

  if ( keydata.isNull() )
  {
    emit messageOut( QString( "PKI bundle  for authid %1: "
                              "insert FAILED, no key data read" ).arg( authid ),
                     authProviderTag(), CRITICAL );
    return pkibundle;
  }

  if ( !pkiconfig.keyPassphrase().isNull() )
  {
    clientkey = QSslKey( keydata, keyAlgorithm_( keydata ),
                         QSsl::Pem, QSsl::PrivateKey, pkiconfig.keyPassphrase().toLocal8Bit() );
  }
  else
  {
    clientkey = QSslKey( keydata, keyAlgorithm_( keydata ) );
  }

  if ( clientkey.isNull() )
  {
    emit messageOut( QString( "PKI bundle  for authid %1: "
                              "insert FAILED, cert key could not be created" ).arg( authid ),
                     authProviderTag(), CRITICAL );
    return pkibundle;
  }

  // init issuer cert
  QSslCertificate issuercert;
  QByteArray issuerdata = fileData_( pkiconfig.issuerId() );
  if ( !issuerdata.isNull() )
  {
    issuercert = QSslCertificate( issuerdata );
    if ( !issuercert.isValid() )
    {
      emit messageOut( QString( "PKI bundle  for authid %1: "
                                "insert FAILED, issuer cert is not valid" ).arg( authid ),
                       authProviderTag(), CRITICAL );
      return pkibundle;
    }
  }

  pkibundle = new QgsPkiPathsBundle( pkiconfig, clientcert, clientkey, issuercert );

  // cache bundle
  putPkiPathsBundle( authid, pkibundle );

  return pkibundle;
}

void QgsAuthProviderPkiPaths::putPkiPathsBundle( const QString &authid, QgsPkiPathsBundle *pkibundle )
{
  emit messageOut( QString( "Putting PKI bundle for authid %1" ).arg( authid ) );
  mPkiPathsBundleCache.insert( authid, pkibundle );
}

void QgsAuthProviderPkiPaths::removePkiPathsBundle( const QString& authid )
{
  if ( mPkiPathsBundleCache.contains( authid ) )
  {
    QgsPkiPathsBundle * pkibundle = mPkiPathsBundleCache.take( authid );
    delete pkibundle;
    pkibundle = 0;
    emit messageOut( QString( "Removed PKI bundle for authid: %1" ).arg( authid ) );
  }
}

#endif
