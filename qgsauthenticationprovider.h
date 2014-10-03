#ifndef QGSAUTHENTICATIONPROVIDER_H
#define QGSAUTHENTICATIONPROVIDER_H

#include <QObject>
#include <QNetworkReply>
#include <QNetworkRequest>

class QgsAuthenticationProvider : public QObject
{
    Q_OBJECT
  public:
    enum ProviderType
    {
      None = 0,
      Basic = 1,
      Unknown = 20, // padding for more standard auth types
#ifndef QT_NO_OPENSSL
      PkiPaths = 21,
#endif
    };

    explicit QgsAuthenticationProvider( QObject *parent = 0 , ProviderType providertype = None );

    ProviderType providerType() { return mType; }

    static bool urlToResource( const QString& accessurl, QString *resource, bool withpath = false );

    const QString typeAsString( QgsAuthenticationProvider::ProviderType providertype = None ) const;

    virtual void updateNetworkRequest( QNetworkRequest &request, const QString& authid ) = 0;

    virtual void updateNetworkReply( QNetworkReply *reply, const QString& authid ) = 0;

  private:
    ProviderType mType;

};

class QgsAuthenticationProviderBasic : public QgsAuthenticationProvider
{
  public:
    QgsAuthenticationProviderBasic( QObject *parent = 0 );

    // QgsAuthenticationProvider interface
    void updateNetworkRequest( QNetworkRequest &request, const QString &authid );
    void updateNetworkReply( QNetworkReply *reply, const QString &authid );
};

#ifndef QT_NO_OPENSSL
class QgsAuthenticationProviderPkiPaths : public QgsAuthenticationProvider
{
  public:
    QgsAuthenticationProviderPkiPaths( QObject *parent = 0 );

    // QgsAuthenticationProvider interface
    void updateNetworkRequest( QNetworkRequest &request, const QString &authid );
    void updateNetworkReply( QNetworkReply *reply, const QString &authid );
};
#endif

#endif // QGSAUTHENTICATIONPROVIDER_H
