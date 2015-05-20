/***************************************************************************
    qgsauthenticationmanager.h
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

#ifndef QGSAUTHENTICATIONMANAGER_H
#define QGSAUTHENTICATIONMANAGER_H

#include <QObject>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QStringList>

#ifndef QT_NO_OPENSSL
#include <QSslCertificate>
#include <QSslKey>
#include <QtCrypto>
#include "qgsauthenticationcertutils.h"
#endif

#include "qgsauthenticationconfig.h"
#include "qgssingleton.h"

namespace QCA
{
  class Initializer;
}
class QgsAuthProvider;

/** \ingroup core
 * Singleton offering an interface to manage the authentication configuration database
 * and to utilize configurations through various providers
 * \since 2.8
 */
class CORE_EXPORT QgsAuthManager : public QObject, public QgsSingleton<QgsAuthManager>
{
    Q_OBJECT
    Q_ENUMS( MessageLevel )

  public:

    enum MessageLevel
    {
      INFO = 0,
      WARNING = 1,
      CRITICAL = 2
    };

    /** Set up the application instance of the auth database connection */
    QSqlDatabase authDbConnection() const;

    /** Name of the auth database table that stores configs */
    const QString authDbConfigTable() const { return smAuthConfigTable; }

    /** Name of the auth database table that stores server exceptions/configs */
    const QString authDbServersTable() const { return smAuthServersTable; }

    /** Initialize QCA, prioritize qca-ossl plugin and optionally set up the auth database */
    bool init();

    /** Whether QCA has the qca-ossl plugin, which a base run-time requirement */
    bool isDisabled() const;

    /** Standard message for when QCA's qca-ossl plugin is missing and system is disabled */
    const QString disabledMessage() const;

    /** The standard auth db file in <user>/.qgis2/ or defined location
     * @see QgsApplication::qgisAuthDbFilePath
     */
    const QString authenticationDbPath() const { return mAuthDbPath; }

    /** Main call to initially set or continually check master password is set
     * @note If it is not set, the user is asked for its input
     * @param verify Whether password's hash was saved in auth database
     */
    bool setMasterPassword( bool verify = false );

    /** Overloaded call to reset master password or set it initially without user interaction
     * @note Only use this in trusted reset functions, unit tests or user/app setup scripts!
     * @param pass Password to use
     * @param verify Whether password's hash was saved in auth database
     */
    bool setMasterPassword( const QString& pass, bool verify = false );

    /** Verify the supplied master password against any existing hash in auth database */
    bool verifyMasterPassword();

    /** Whether master password has be input and verified, i.e. auth database is accessible */
    bool masterPasswordIsSet() const;

    /** Verify a password hash existing in auth database */
    bool masterPasswordHashInDb() const;

    /** Clear supplied master password
     * @note This will not necessarily clear authenticated connections cached in network connection managers
     */
    void clearMasterPassword() { mMasterPass = QString(); }

    /** Check whether supplied password is the same as the one already set
     * @param pass Password to verify
     */
    bool masterPasswordSame( const QString& pass ) const;

    /** Reset the master password to a new one, then re-encrypt all previous
     * configs in a new database file, optionally backup curren database
     * @param newpass New master password to replace existing
     * @param oldpass Current master password to replace existing
     * @param keepbackup Whether to keep the genereated backup of current database
     * @param backuppath Where the backup is located, if kept
     */
    bool resetMasterPassword( const QString& newpass, const QString& oldpass, bool keepbackup, QString *backuppath = 0 );

    /** Simple text tag describing authentication system for message logs */
    const QString authManTag() const { return smAuthManTag; }


    /** Instantiate and register existing auth providers */
    void registerProviders();

    /** Sync the confg/provider cache with what is in database */
    void updateConfigProviderTypes();

    /**
     * Get provider from the config/provider cache
     * @param authcfg Authentication config id
     */
    QgsAuthProvider* configProvider( const QString& authcfg );

    /**
     * Get type of provider as an enum
     * @param authcfg
     */
    QgsAuthType::ProviderType configProviderType( const QString& authcfg );

    /** Get a unique generated 7-character string to assign to as config id */
    const QString uniqueConfigId() const;

    /**
     * Verify if provided authentication id is unique
     * @param id Id to check
     */
    bool configIdUnique( const QString &id ) const;

    /** Get list of authentication ids from database */
    QStringList configIds() const;

    /** Get mapping of authentication ids and their base configs (not decrypted data) */
    QHash<QString, QgsAuthConfigBase> availableConfigs();


    /**
     * Store an authentication config in the database
     * @param config Associated authentication config id
     * @return Whether operation succeeded
     */
    bool storeAuthenticationConfig( QgsAuthConfigBase &config );

    /**
     * Update an authentication config in the database
     * @param config Associated authentication config id
     * @return Whether operation succeeded
     */
    bool updateAuthenticationConfig( const QgsAuthConfigBase& config );

    /**
     * Load an authentication config from the database into subclass
     * @param authcfg Associated authentication config id
     * @param config Subclassed config to load into
     * @param full Whether to decrypt and populate all sensitive data in subclass
     * @return Whether operation succeeded
     */
    bool loadAuthenticationConfig( const QString& authcfg, QgsAuthConfigBase &config, bool full = false );

    /**
     * Remove an authentication config in the database
     * @param config Associated authentication config id
     * @return Whether operation succeeded
     */
    bool removeAuthenticationConfig( const QString& authcfg );

    /**
     * Clear all authentication configs from table in database and from provider caches
     * @return Whether operation succeeded
     */
    bool removeAllAuthenticationConfigs();

    /**
     * Erase all rows from all tables in authentication database
     * @return Whether operation succeeded
     */
    bool eraseAuthenticationDatabase();


    ////////////////// Provider calls ///////////////////////

    /**
     * Provider call to update a QNetworkRequest with an authentication config
     * @param request The QNetworkRequest
     * @param authcfg Associated authentication config id
     * @return Whether operation succeeded
     */
    bool updateNetworkRequest( QNetworkRequest &request, const QString& authcfg );

    /**
     * Provider call to update a QNetworkReply with an authentication config (used to skip known SSL errors, etc.)
     * @param reply The QNetworkReply
     * @param authcfg Associated authentication config id
     * @return Whether operation succeeded
     */
    bool updateNetworkReply( QNetworkReply *reply, const QString& authcfg );

    ////////////////// Generic settings ///////////////////////

    /** Store an authentication setting (stored as string via QVariant( value ).toString() ) */
    bool storeAuthSetting( const QString& key, QVariant value, bool encrypt = false );

    /** Get an authentication setting (retrieved as string and returned as QVariant( QString )) */
    QVariant getAuthSetting( const QString& key, QVariant defaultValue = QVariant(), bool decrypt = false );

    /** Check if an authentication setting exists */
    bool existsAuthSetting( const QString& key );

    /** Remove an authentication setting */
    bool removeAuthSetting( const QString& key );

#ifndef QT_NO_OPENSSL
    ////////////////// Certificate calls ///////////////////////

    /** Store a certificate identity */
    bool storeCertIdentity( const QSslCertificate& cert, const QSslKey& key );

    /** Get a certificate identity by id (sha hash) */
    const QSslCertificate getCertIdentity( const QString& id );

    /** Get a certificate identity bundle by id (sha hash) */
    const QPair<QSslCertificate, QSslKey> getCertIdentityBundle( const QString& id );

    /** Get certificate identities */
    const QList<QSslCertificate> getCertIdentities();

    /** Check if a certificate identity exists */
    bool existsCertIdentity( const QString& id );

    /** Remove a certificate identity */
    bool removeCertIdentity( const QString& id );


    /** Store an SSL certificate custom config */
    bool storeSslCertCustomConfig( const QgsAuthConfigSslServer& config );

    /** Get an SSL certificate custom config by id (sha hash) */
    const QgsAuthConfigSslServer getSslCertCustomConfig( const QString& id );

    /** Get an SSL certificate custom config by host:port */
    const QgsAuthConfigSslServer getSslCertCustomConfigByHost( const QString& hostport );

    /** Get SSL certificate custom configs */
    const QList<QgsAuthConfigSslServer> getSslCertCustomConfigs();

    /** Check if SSL certificate custom config exists */
    bool existsSslCertCustomConfig( const QString& id );

    /** Remove an SSL certificate custom config */
    bool removeSslCertCustomConfig( const QString& id );


    /** Store multiple certificate authorities */
    bool storeCertAuthorities( const QList<QSslCertificate>& certs );

    /** Store a certificate authority */
    bool storeCertAuthority( const QSslCertificate& cert );

    /** Get a certificate authority by id (sha hash) */
    const QSslCertificate getCertAuthority( const QString& id );

    /** Check if a certificate authority exists */
    bool existsCertAuthority( const QSslCertificate& cert );

    /** Remove a certificate authority */
    bool removeCertAuthority( const QSslCertificate& cert );

    /** Get root system certificate authorities */
    const QList<QSslCertificate> getSystemRootCAs();

    /** Get extra file-based certificate authorities */
    const QList<QSslCertificate> getExtraFileCAs();

    /** Get database-stored certificate authorities */
    const QList<QSslCertificate> getDatabaseCAs();

    /** Get sha1-mapped database-stored certificate authorities */
    const QMap<QString, QSslCertificate> getMappedDatabaseCAs();

    /** Get all CA certs mapped to their sha1 from cache */
    const QMap<QString, QPair<QgsAuthCertUtils::CaCertSource , QSslCertificate> > getCaCertsCache()
    {
      return mCaCertsCache;
    }

    /** Rebuild certificate authority cache */
    void rebuildCaCertsCache();

    /** Store user trust value for a certificate */
    bool storeCertTrustPolicy( const QSslCertificate& cert, QgsAuthCertUtils::CertTrustPolicy policy );

    /** Get a whether certificate is trusted by user
        @return DefaultTrust if certificate sha not in trust table, i.e. follows default trust policy
    */
    QgsAuthCertUtils::CertTrustPolicy getCertTrustPolicy( const QSslCertificate& cert );

    /** Remove a group certificate authorities */
    bool removeCertTrustPolicies( const QList<QSslCertificate>& certs );

    /** Remove a certificate authority */
    bool removeCertTrustPolicy( const QSslCertificate& cert );

    /** Get trust policy for a particular certificate */
    QgsAuthCertUtils::CertTrustPolicy getCertificateTrustPolicy( const QSslCertificate& cert );

    /** Set the default certificate trust policy perferred by user */
    bool setDefaultCertTrustPolicy( QgsAuthCertUtils::CertTrustPolicy policy );

    /** Get the default certificate trust policy perferred by user */
    QgsAuthCertUtils::CertTrustPolicy defaultCertTrustPolicy();

    /** Get cache of certificate sha1s, per trust policy */
    const QMap<QgsAuthCertUtils::CertTrustPolicy, QStringList > getCertTrustCache() { return mCertTrustCache; }

    /** Rebuild certificate authority cache */
    bool rebuildCertTrustCache();

    /** Get list of all trusted CA certificates */
    const QList<QSslCertificate> getTrustedCaCerts( bool includeinvalid = false );

    /** Get list of all untrusted CA certificates */
    const QList<QSslCertificate> getUntrustedCaCerts( QList<QSslCertificate> trustedCAs = QList<QSslCertificate>() );

    /** Rebuild trusted certificate authorities cache */
    bool rebuildTrustedCaCertsCache();

    /** Get cache of trusted certificate authorities, ready for network connections */
    const QList<QSslCertificate> getTrustedCaCertsCache() { return mTrustedCaCertsCache; }

    /** Get concatenated string of all trusted CA certificates */
    const QByteArray getTrustedCaCertsPemText( bool includeinvalid = false );

#endif

  signals:
    /**
     * Custom logging signal to relay to console output and QgsMessageLog
     * @see QgsMessageLog
     * @param message Message to send
     * @param tag Associated tag (title)
     * @param level Message log level
     */
    void messageOut( const QString& message, const QString& tag = smAuthManTag, QgsAuthManager::MessageLevel level = INFO ) const;

    /**
     * Emmitted when a password has been verify (or not)
     * @param verified The state of password's verification
     */
    void masterPasswordVerified( bool verified ) const;

  public slots:
    /** Clear all authentication configs from provider caches */
    void clearAllCachedConfigs();

    /** Clear an authentication config from its associated provider cache */
    void clearCachedConfig(const QString& authcfg );

  private slots:
    void writeToConsole( const QString& message, const QString& tag = QString(), QgsAuthManager::MessageLevel level = INFO );

  protected:
    explicit QgsAuthManager();
    ~QgsAuthManager();

    friend class QgsSingleton<QgsAuthManager>; // Let QgsSingleton access protected constructor

  private:

    bool createConfigTables();

    bool createCertTables();

    bool masterPasswordInput();

    bool masterPasswordRowsInDb( int *rows ) const;

    bool masterPasswordCheckAgainstDb() const;

    bool masterPasswordStoreInDb() const;

    bool masterPasswordClearDb();

    const QString masterPasswordCiv() const;

    bool verifyPasswordCanDecryptConfigs() const;

    bool reencryptAllAuthenticationConfigs( const QString& prevpass, const QString& prevciv );

    bool reencryptAuthenticationConfig( const QString& authcfg, const QString& prevpass, const QString& prevciv );

    bool authDbOpen() const;

    bool authDbQuery( QSqlQuery *query ) const;

    bool authDbStartTransaction() const;

    bool authDbCommit() const;

    bool authDbTransactionQuery( QSqlQuery *query ) const;

#ifndef QT_NO_OPENSSL
    void insertCaCertInCache( QgsAuthCertUtils::CaCertSource source, const QList<QSslCertificate> &certs );
#endif

    const QString authDbPassTable() const { return smAuthPassTable; }

    const QString authDbSettingsTable() const { return smAuthSettingsTable; }

    const QString authDbIdentitiesTable() const { return smAuthIdentitiesTable; }

    const QString authDbAuthoritiesTable() const { return smAuthAuthoritiesTable; }

    const QString authDbTrustTable() const { return smAuthTrustTable; }

    static QgsAuthManager* smInstance;
    static const QString smAuthConfigTable;
    static const QString smAuthPassTable;
    static const QString smAuthSettingsTable;
    static const QString smAuthIdentitiesTable;
    static const QString smAuthServersTable;
    static const QString smAuthAuthoritiesTable;
    static const QString smAuthTrustTable;
    static const QString smAuthManTag;

    QString mAuthDbPath;

    QCA::Initializer * mQcaInitializer;

    QHash<QString, QgsAuthType::ProviderType> mConfigProviders;
    QHash<QgsAuthType::ProviderType, QgsAuthProvider*> mProviders;
    bool mProvidersRegistered;

    QString mMasterPass;
    bool mAuthDisabled;

#ifndef QT_NO_OPENSSL
    // mapping of sha1 digest and cert source and cert
    // appending removes duplicates
    QMap<QString, QPair<QgsAuthCertUtils::CaCertSource , QSslCertificate> > mCaCertsCache;
    // list of sha1 digests per policy
    QMap<QgsAuthCertUtils::CertTrustPolicy, QStringList > mCertTrustCache;
    // cache of certs ready to be utilized in network connections
    QList<QSslCertificate> mTrustedCaCertsCache;
#endif
};

#endif // QGSAUTHENTICATIONMANAGER_H
