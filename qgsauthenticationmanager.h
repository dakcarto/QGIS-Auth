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

    const QString authDbTable() const { return smAuthConfigTable; }


    bool inputMasterPassword();

    bool resetMasterPassword();

    bool configIdUnique(const QString &id) const;

    const QString uniqueConfigId() const;


    bool saveAuthenticationConfig( const QgsAuthenticationConfig& config ) const;

    bool loadAuthenticationConfig(const QString& id, QgsAuthenticationConfig &config ) const;

  signals:
    void messageOut( const QString &message, const QString &tag = smAuthManTag, MessageLevel level = INFO ) const;

  public slots:

  private slots:
    void writeDebug( const QString& message, const QString& tag = QString(), MessageLevel level = INFO );

  protected:
    explicit QgsAuthenticationManager( QObject *parent = 0 );
    ~QgsAuthenticationManager();

  private:
    bool verifyMasterPassword();

    bool checkMasterPasswordEncrypt() const;

    bool sameMasterPassword( const QString& pass ) const;

    QStringList configIds() const;

    QSqlQuery queryAuthDb( const QString &query, bool * ok ) const;

    static QgsAuthenticationManager* smInstance;
    static const QString smAuthConfigTable;
    static const QString smAuthCheckTable;
    static const QString smAuthManTag;

    QString mMasterPass;

};

#endif // QGSAUTHENTICATIONMANAGER_H
