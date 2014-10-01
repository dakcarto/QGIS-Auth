#ifndef QGSAUTHENTICATIONMANAGER_H
#define QGSAUTHENTICATIONMANAGER_H

#include <QObject>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QStringList>

#include "qgsauthenticationconfig.h"


class QgsAuthenticationManager : public QObject
{
    Q_OBJECT
  public:

    // TODO: switch to QgsMessageLog enum
    enum MessageLevel
    {
      INFO = 0,
      WARNING = 1,
      CRITICAL = 2
    };

    static QgsAuthenticationManager *instance();

    QSqlDatabase authDbConnection() const;

    bool initAuthDatabase() const;

    bool setMasterPassword( bool verify = false );

    bool masterPasswordIsSet() const;

    void clearMasterPassword() { mMasterPass = QString(); }

    bool masterPasswordSame( const QString& pass ) const;

    bool resetMasterPassword();

    bool configIdUnique( const QString &id ) const;

    const QString uniqueConfigId() const;


    bool saveAuthenticationConfig( const QgsAuthenticationConfig& config ) const;

    bool loadAuthenticationConfig( const QString& id, QgsAuthenticationConfig &config ) const;

  signals:
    void messageOut( const QString &message, const QString &tag = smAuthManTag, MessageLevel level = INFO ) const;

    void masterPasswordVerified( bool verified ) const;

  public slots:

  private slots:
    void writeDebug( const QString& message, const QString& tag = QString(), MessageLevel level = INFO );

  protected:
    explicit QgsAuthenticationManager( QObject *parent = 0 );
    ~QgsAuthenticationManager();

  private:

    bool masterPasswordInput();

    bool masterPasswordResetInput();

    bool masterPasswordRowsInDb( int *rows ) const;

    bool masterPasswordCheckAgainstDb() const;

    bool masterPasswordStoreInDb() const;

    bool masterPasswordClearDb() const;

    QStringList authDbConfigIds() const;

    bool authDbOpen() const;

    bool authDbQuery( QSqlQuery *query ) const;

    bool authDbStartTransaction() const;

    bool authDbCommit() const;

    bool authDbTransactionQuery( QSqlQuery *query ) const;

    const QString authDbPassTable() const { return smAuthPassTable; }
    const QString authDbConfigTable() const { return smAuthConfigTable; }
    const QString authManTag() const { return smAuthManTag; }

    static QgsAuthenticationManager* smInstance;
    static const QString smAuthConfigTable;
    static const QString smAuthPassTable;
    static const QString smAuthManTag;

    QString mMasterPass;
    QString mMasterPassReset;
};

#endif // QGSAUTHENTICATIONMANAGER_H
