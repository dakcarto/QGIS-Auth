#ifndef QGSAUTHENTICATIONCONFIG_H
#define QGSAUTHENTICATIONCONFIG_H

#include <QString>

class QgsAuthenticationConfig
{
  public:
    enum ConfigType
    {
      Basic,
      PkiPaths,
      Unknown
    };

    QgsAuthenticationConfig( ConfigType type = Unknown, int version = 0 );

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

    virtual bool isValid();

  private:
    QString mId;
    QString mName;
    QString mUri;
    ConfigType mType;
    int mVersion;
};

class QgsAuthenticationConfigBasic: public QgsAuthenticationConfig
{
  public:
    QgsAuthenticationConfigBasic();

    const QString username() const { return mUsername; }
    void setUsername( const QString& name ) { mUsername = name; }

    const QString password() const { return mPassword; }
    void setPassword( const QString& pass ) { mPassword = pass; }

    bool isValid();

  private:
    QString mUsername;
    QString mPassword;
};

class QgsAuthenticationConfigPkiPaths: public QgsAuthenticationConfig
{
  public:
    QgsAuthenticationConfigPkiPaths();

    const QString certPath() const { return mCertPath; }
    void setCertPath( const QString& path ) { mCertPath = path; }

    const QString keyPath() const { return mKeyPath; }
    void setKeyPath( const QString& path ) { mKeyPath = path; }

    const QString keyPassphrase() const { return mKeyPass; }
    void setKeyPassphrase( const QString& passphrase ) { mKeyPass = passphrase; }

    const QString issuerPath() const { return mIssuerPath; }
    void setIssuerPath( const QString& path ) { mIssuerPath = path; }

    bool issuerSelfSigned() const { return mIssuerSelf; }
    void setIssuerSelfSigned( bool seflsigned ) { mIssuerSelf = seflsigned; }

    bool isValid();

  private:
    QString mCertPath;
    QString mKeyPath;
    QString mKeyPass;
    QString mIssuerPath;
    bool mIssuerSelf;
};

#endif // QGSAUTHENTICATIONCONFIG_H
