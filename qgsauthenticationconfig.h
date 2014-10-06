#ifndef QGSAUTHENTICATIONCONFIG_H
#define QGSAUTHENTICATIONCONFIG_H

#include <QHash>
#include <QString>


class QgsAuthType
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

    static const QHash<ProviderType, QString> typeNameHash();

    static ProviderType providerTypeFromInt( int itype );

    static const QString typeToString( ProviderType providertype = None );

    static ProviderType stringToType( const QString& name );

    static const QString typeDescription( ProviderType providertype = None );
};

/**
 * @brief Base class for configs
 */
class QgsAuthConfigBase
{
  public:

    QgsAuthConfigBase( QgsAuthType::ProviderType type = QgsAuthType::None, int version = 0 );

    QgsAuthConfigBase( const QgsAuthConfigBase& config );

    virtual ~QgsAuthConfigBase() {}

    const QString id() const { return mId; }
    void setId( const QString& id ) { mId = id; }

    const QString name() const { return mName; }
    void setName( const QString& name ) { mName = name; }

    const QString uri() const { return mUri; }
    void setUri( const QString& uri ) { mUri = uri; }

    QgsAuthType::ProviderType type() const { return mType; }
    void setType( QgsAuthType::ProviderType ptype ) { mType = ptype; }

    int version() const { return mVersion; }
    void setVersion( int version ) { mVersion = version; }

    const QString typeToString() const;

    const QgsAuthConfigBase& asBaseConfig();

    virtual bool isValid( bool validateid = false ) const;

    virtual const QString configString() const { return QString(); }
    virtual void loadConfigString( const QString& config ) { Q_UNUSED( config ); }

    const QgsAuthConfigBase toBaseConfig();

  protected:
    QString mId;
    QString mName;
    QString mUri;
    QgsAuthType::ProviderType mType;
    int mVersion;

    static const QString mConfSep;
};


class QgsAuthConfigBasic: public QgsAuthConfigBase
{
  public:
    QgsAuthConfigBasic();

    QgsAuthConfigBasic( const QgsAuthConfigBase& config )
        : QgsAuthConfigBase( config ) {}

    ~QgsAuthConfigBasic() {}

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

class QgsAuthConfigPkiPaths: public QgsAuthConfigBase
{
  public:
    QgsAuthConfigPkiPaths();

    QgsAuthConfigPkiPaths( const QgsAuthConfigBase& config )
        : QgsAuthConfigBase( config ) {}

    ~QgsAuthConfigPkiPaths() {}

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
