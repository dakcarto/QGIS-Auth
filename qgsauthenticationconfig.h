#ifndef QGSAUTHENTICATIONCONFIG_H
#define QGSAUTHENTICATIONCONFIG_H

#include <QString>

/**
 * @brief Abstract base class for configs
 */
class QgsAuthenticationConfigBase
{
  public:
    enum ConfigType
    {
      None,
      Basic,
      PkiPaths,
      Unknown
    };

    QgsAuthenticationConfigBase( ConfigType type = Unknown, int version = 0 );

    const QString id() const { return mId; }
    void setId( const QString& id ) { mId = id; }

    const QString name() const { return mName; }
    void setName( const QString& name ) { mName = name; }

    const QString uri() const { return mUri; }
    void setUri( const QString& uri ) { mUri = uri; }

    ConfigType type() const { return mType; }
    void setType( ConfigType i ) { mType = i; }

    int version() const { return mVersion; }
    void setVersion( int i ) { mVersion = i; }

    const QString typeAsString() const;

    const QgsAuthenticationConfigBase& asBaseConfig();

    virtual bool isValid() const;

    virtual const QString configString() const = 0;
    virtual void loadConfigString( const QString& config ) = 0;

  protected:
    QString mId;
    QString mName;
    QString mUri;
    ConfigType mType;
    int mVersion;
    static const QString mConfSep;
};

class QgsAuthenticationConfig: public QgsAuthenticationConfigBase
{
  public:
    QgsAuthenticationConfig( ConfigType type = None, int version = 0 );
};

class QgsAuthenticationConfigBasic: public QgsAuthenticationConfigBase
{
  public:
    QgsAuthenticationConfigBasic();

    const QString realm() const { return mRealm; }
    void setRealm( const QString& realm ) { mRealm = realm; }

    const QString username() const { return mUsername; }
    void setUsername( const QString& name ) { mUsername = name; }

    const QString password() const { return mPassword; }
    void setPassword( const QString& pass ) { mPassword = pass; }

    bool isValid() const;

    const QString configString() const;
    void loadConfigString( const QString& config );

  private:
    QString mRealm;
    QString mUsername;
    QString mPassword;
};

class QgsAuthenticationConfigPki: public QgsAuthenticationConfigBase
{
  public:
    QgsAuthenticationConfigPki();

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

    bool isValid() const;

    const QString configString() const;
    void loadConfigString( const QString& config );

  private:
    QString mCertId;
    QString mKeyId;
    QString mKeyPass;
    QString mIssuerId;
    bool mIssuerSelf;
};

#endif // QGSAUTHENTICATIONCONFIG_H
