#ifndef QGSAUTHENTICATIONCONFIG_H
#define QGSAUTHENTICATIONCONFIG_H

#include <QString>

class QgsAuthenticationProvider;

/**
 * @brief Base class for configs
 */
class QgsAuthenticationConfigBase
{
  public:
    enum ProviderType
    {
      None = 0,
      Basic = 1,
#ifndef QT_NO_OPENSSL
      PkiPaths = 2,
#endif
      Unknown = 20 // padding for more standard auth types
    };

    QgsAuthenticationConfigBase( ProviderType type = None,
                                 int version = 0 );

    QgsAuthenticationConfigBase( const QgsAuthenticationConfigBase& config );

    const QString id() const { return mId; }
    void setId( const QString& id ) { mId = id; }

    const QString name() const { return mName; }
    void setName( const QString& name ) { mName = name; }

    const QString uri() const { return mUri; }
    void setUri( const QString& uri ) { mUri = uri; }

    ProviderType type() const { return mType; }
    void setType( ProviderType i ) { mType = i; }

    int version() const { return mVersion; }
    void setVersion( int version ) { mVersion = version; }

    const QString typeAsString() const;

    const QgsAuthenticationConfigBase& asBaseConfig();

    virtual bool isValid( bool validateid = false ) const;

    virtual const QString configString() const { return QString(); }
    virtual void loadConfigString( const QString& config ) { Q_UNUSED( config ); }

    const QgsAuthenticationConfigBase toBaseConfig();

  protected:
    QString mId;
    QString mName;
    QString mUri;
    ProviderType mType;
    int mVersion;

    static const QString mConfSep;
};


class QgsAuthenticationConfigBasic: public QgsAuthenticationConfigBase
{
  public:
    QgsAuthenticationConfigBasic();

    QgsAuthenticationConfigBasic( const QgsAuthenticationConfigBase& config )
        : QgsAuthenticationConfigBase( config ) {}

    const QString realm() const { return mRealm; }
    void setRealm( const QString& realm ) { mRealm = realm; }

    const QString username() const { return mUsername; }
    void setUsername( const QString& name ) { mUsername = name; }

    const QString password() const { return mPassword; }
    void setPassword( const QString& pass ) { mPassword = pass; }

    bool isValid( bool validateid = false ) const;

    const QString configString() const;
    void loadConfigString( const QString& config = QString() );

  private:
    QString mRealm;
    QString mUsername;
    QString mPassword;
};

class QgsAuthenticationConfigPkiPaths: public QgsAuthenticationConfigBase
{
  public:
    QgsAuthenticationConfigPkiPaths();

    QgsAuthenticationConfigPkiPaths( const QgsAuthenticationConfigBase& config )
        : QgsAuthenticationConfigBase( config ) {}

    const QString certId() const { return mCertId; }
    void setCertId( const QString& id ) { mCertId = id; }

    const QString keyId() const { return mKeyId; }
    void setKeyId( const QString& id ) { mKeyId = id; }

    const QString keyPassphrase() const { return mKeyPass; }
    void setKeyPassphrase( const QString& passphrase ) { mKeyPass = passphrase; }

    const QString issuerId() const { return mIssuerId; }
    void setIssuerId( const QString& id ) { mIssuerId = id; }

    bool issuerSelfSigned() const { return mIssuerSelf; }
    void setIssuerSelfSigned( bool selfsigned ) { mIssuerSelf = selfsigned; }

    bool isValid( bool validateid = false ) const;

    const QString configString() const;
    void loadConfigString( const QString& config = QString() );

  private:
    QString mCertId;
    QString mKeyId;
    QString mKeyPass;
    QString mIssuerId;
    bool mIssuerSelf;
};

#endif // QGSAUTHENTICATIONCONFIG_H
