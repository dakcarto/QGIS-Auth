#include "qgsauthenticationprovider.h"

#include "qgsauthenticationconfig.h"
#include "qgsauthenticationmanager.h"

QgsAuthenticationProvider::QgsAuthenticationProvider( QObject *parent, ProviderType providertype )
    : QObject( parent )
    , mType( providertype )
{
}

QgsAuthenticationProvider::ProviderType QgsAuthenticationProvider::providerTypeFromInt( int itype )
{
  ProviderType ptype = Unknown;
  switch ( itype )
  {
    case 0:
      ptype = None;
      break;
    case 1:
      ptype = None;
      break;
#ifndef QT_NO_OPENSSL
    case 2:
      ptype = PkiPaths;
      break;
#endif
    case 20:
      // Unknown
      break;
    default:
      break;
  }

  return ptype;
}

const QString QgsAuthenticationProvider::typeAsString( QgsAuthenticationProvider::ProviderType providertype )
{
  QString s = tr( "No authentication configuration set" );
  switch ( providertype )
  {
    case None:
      break;
    case Basic:
      s = tr( "Basic authentication configuration" );
      break;
#ifndef QT_NO_OPENSSL
    case PkiPaths:
      s = tr( "PKI paths authentication configuration" );
      break;
#endif
    case Unknown:
      s = tr( "Unsupported authentication configuration" );
      break;
    default:
      break;
  }
  return s;
}

bool QgsAuthenticationProvider::urlToResource( const QString &accessurl, QString *resource, bool withpath )
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

QgsAuthenticationProviderBasic::QgsAuthenticationProviderBasic( QObject *parent )
    : QgsAuthenticationProvider( parent, Basic )
{
}

void QgsAuthenticationProviderBasic::updateNetworkRequest( QNetworkRequest &request, const QString &authid )
{
}

void QgsAuthenticationProviderBasic::updateNetworkReply( QNetworkReply *reply, const QString &authid )
{
}

#ifndef QT_NO_OPENSSL

QgsAuthenticationProviderPkiPaths::QgsAuthenticationProviderPkiPaths( QObject *parent )
    : QgsAuthenticationProvider( parent, PkiPaths )
{

}

void QgsAuthenticationProviderPkiPaths::updateNetworkRequest( QNetworkRequest &request, const QString &authid )
{
}

void QgsAuthenticationProviderPkiPaths::updateNetworkReply( QNetworkReply *reply, const QString &authid )
{
}

#endif


