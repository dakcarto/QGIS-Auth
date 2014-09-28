#ifndef QGSAUTHENTICATIONMANAGER_H
#define QGSAUTHENTICATIONMANAGER_H

#include <QObject>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>

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

    bool initAuthDatabase();


//    const QString authDatabaseModel() const;

  signals:
    void messageOut( const QString &message, const QString &tag = QString(), MessageLevel level = INFO );

  public slots:

  private slots:
    void writeDebug( const QString& message, const QString& tag = QString(), MessageLevel level = INFO );

    bool queryDb( const QString &query, QSqlDatabase db );

  protected:
    explicit QgsAuthenticationManager( QObject *parent = 0 );
    ~QgsAuthenticationManager();

  private:
    static QgsAuthenticationManager* smInstance;

};

#endif // QGSAUTHENTICATIONMANAGER_H
