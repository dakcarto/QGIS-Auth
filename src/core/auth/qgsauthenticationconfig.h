/***************************************************************************
    qgsauthenticationconfig.h
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

#ifndef QGSAUTHENTICATIONCONFIG_H
#define QGSAUTHENTICATIONCONFIG_H

#include <QHash>
#include <QString>

#ifndef QT_NO_OPENSSL
#include <QSslCertificate>
#include <QSslError>
#include <QSslSocket>
#endif

class CORE_EXPORT QgsAuthType
{
  public:
    enum ProviderType
    {
      None = 0,
      Basic = 1,
#ifndef QT_NO_OPENSSL
      PkiPaths = 2,
      PkiPkcs12 = 3,
      IdentityCert = 4,
#endif
      Unknown = 20 // padding for more standard auth types
    };

    static const QHash<QgsAuthType::ProviderType, QString> typeNameHash();

    static QgsAuthType::ProviderType providerTypeFromInt( int itype );

    static const QString typeToString( QgsAuthType::ProviderType providertype = None );

    static QgsAuthType::ProviderType stringToType( const QString& name );

    static const QString typeDescription( QgsAuthType::ProviderType providertype = None );
};

/**
 * @brief Base class for configs
 */
class CORE_EXPORT QgsAuthConfigBase
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


class CORE_EXPORT QgsAuthConfigBasic: public QgsAuthConfigBase
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

class CORE_EXPORT QgsAuthConfigPkiPaths: public QgsAuthConfigBase
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

    const QString certAsPem() const;

    const QStringList keyAsPem( bool reencrypt = true ) const;

    bool isValid( bool validateid = false ) const;

    const QString configString() const;
    void loadConfigString( const QString& config = QString() );

  private:
    QString mCertId;
    QString mKeyId;
    QString mKeyPass;
};

class CORE_EXPORT QgsAuthConfigPkiPkcs12: public QgsAuthConfigBase
{
  public:
    QgsAuthConfigPkiPkcs12();

    QgsAuthConfigPkiPkcs12( const QgsAuthConfigBase& config )
        : QgsAuthConfigBase( config ) {}

    ~QgsAuthConfigPkiPkcs12() {}

    const QString bundlePath() const { return mBundlePath; }
    void setBundlePath( const QString& path ) { mBundlePath = path; }

    const QString bundlePassphrase() const { return mBundlePass; }
    void setBundlePassphrase( const QString& passphrase ) { mBundlePass = passphrase; }

    const QString certAsPem() const;

    const QStringList keyAsPem( bool reencrypt = true ) const;

    bool isValid( bool validateid = false ) const;

    const QString configString() const;
    void loadConfigString( const QString& config = QString() );

  private:
    QString mBundlePath;
    QString mBundlePass;
};

class CORE_EXPORT QgsAuthConfigIdentityCert: public QgsAuthConfigBase
{
  public:
    QgsAuthConfigIdentityCert();

    QgsAuthConfigIdentityCert( const QgsAuthConfigBase& config )
        : QgsAuthConfigBase( config ) {}

    ~QgsAuthConfigIdentityCert() {}

    const QString certId() const { return mCertId; }
    void setCertId( const QString& id ) { mCertId = id; }

    const QString certAsPem() const;

    const QStringList keyAsPem( bool reencrypt = true ) const;

    bool isValid( bool validateid = false ) const;

    const QString configString() const;
    void loadConfigString( const QString& config = QString() );

  private:
    QString mCertId;
};

#ifndef QT_NO_OPENSSL
class CORE_EXPORT QgsAuthConfigSslServer
{
  public:
    QgsAuthConfigSslServer();

    ~QgsAuthConfigSslServer() {}

    const QSslCertificate sslCertificate() const { return mSslCert; }
    void setSslCertificate( const QSslCertificate& cert ) { mSslCert = cert; }

    const QString sslHost() const  { return mSslHost; }
    void setSslHost( const QString& host ) { mSslHost = host; }

    QSsl::SslProtocol sslProtocol() const { return mSslProtocol; }
    void setSslProtocol( QSsl::SslProtocol protocol ) { mSslProtocol = protocol; }

    const QList<QSslError> sslIgnoredErrors() const;
    const QList<QSslError::SslError> sslIgnoredErrorEnums() const { return mSslIgnoredErrors; }
    void setSslIgnoredErrorEnums( const QList<QSslError::SslError>& errors ) { mSslIgnoredErrors = errors; }

    const QPair<QSslSocket::PeerVerifyMode, int> sslPeerVerify() const { return mSslPeerVerify; }
    void setSslPeerVerify( const QPair<QSslSocket::PeerVerifyMode, int>& modedepth ) {
      mSslPeerVerify = modedepth;
    }

    int version() const { return mVersion; }
    void setVersion( int version ) { mVersion = version; }

    int qtVersion() const { return mQtVersion; }
    void setQtVersion( int version ) { mQtVersion = version; }

    const QString configString() const;
    void loadConfigString( const QString& config = QString() );

    bool isNull() const;

  private:

    QString mSslHost;
    QSslCertificate mSslCert;

    QSsl::SslProtocol mSslProtocol;
    int mQtVersion;
    QList<QSslError::SslError> mSslIgnoredErrors;
    QPair<QSslSocket::PeerVerifyMode, int> mSslPeerVerify;
    int mVersion;

    static const QString mConfSep;
};
#endif

#endif // QGSAUTHENTICATIONCONFIG_H
