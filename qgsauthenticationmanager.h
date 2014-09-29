#ifndef QGSAUTHENTICATIONMANAGER_H
#define QGSAUTHENTICATIONMANAGER_H

#include <QObject>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QStringList>

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

    const QString uniqueConfigId() const;

    bool configIdUnique(const QString &id) const;

    void inputMasterPassword();
    bool resetMasterPassword();

    const QString generateConfigId() const;

//    const QString authDatabaseModel() const;

  signals:
    void messageOut( const QString &message, const QString &tag = QString(), MessageLevel level = INFO ) const;

  public slots:

  private slots:
    void writeDebug( const QString& message, const QString& tag = QString(), MessageLevel level = INFO );

  protected:
    explicit QgsAuthenticationManager( QObject *parent = 0 );
    ~QgsAuthenticationManager();

  private:
    static QgsAuthenticationManager* smInstance;
    static const QString smAuthConfigTable;
    QString mMasterPass;

    QStringList configIds() const;

    QSqlQuery queryAuthDb( const QString &query, bool * ok ) const;

};

#endif // QGSAUTHENTICATIONMANAGER_H
