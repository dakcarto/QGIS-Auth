#include "qgsauthenticationprovider.h"

#include "qgsauthenticationconfig.h"
#include "qgsauthenticationmanager.h"

QgsAuthenticationProvider::QgsAuthenticationProvider( QObject *parent, ProviderType providertype )
    : QObject( parent )
    , mType( providertype )
{
}

bool QgsAuthenticationProvider::urlToResource( const QString &accessurl, QString *resource, bool withpath )
{
  QString res = QString();
  if ( !accessurl.isEmpty() )
  {
    QUrl url( accessurl );
    if ( url.isValid() )
    {
      res = QString( "%1://%2:%3%4" ).arg( url.scheme() ).arg( url.host() ).arg( url.port() ).arg( withpath ? url.path() : );
    }
  }
  *resource = res;
  return ( !res.isEmpty() );
}

const QString QgsAuthenticationProvider::typeAsString(QgsAuthenticationProvider::ProviderType providertype ) const
{
  QString s = tr( "No authentication configuration set" );
  switch ( providertype )
  {
    case None:
      break;
    case Basic:
      s = tr( "Basic authentication configuration" );
    case Unknown:
      s = tr( "Unsupported authentication configuration" );
#ifndef QT_NO_OPENSSL
    case PkiPaths:
      s = tr( "PKI paths authentication configuration" );
#endif
    default:
      break;
  }
  return s;
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
{

}

void QgsAuthenticationProviderPkiPaths::updateNetworkRequest( QNetworkRequest &request, const QString &authid )
{
}

void QgsAuthenticationProviderPkiPaths::updateNetworkReply( QNetworkReply *reply, const QString &authid )
{
}

#endif


