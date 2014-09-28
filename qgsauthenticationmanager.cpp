#include "qgsauthenticationmanager.h"

#include <QFileInfo>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>




#include "qgsapplication.h"


QgsAuthenticationManager *QgsAuthenticationManager::smInstance = 0;
//QMap<QString, QgsAuthPkiGroup *> QgsAuthenticationManager::mAuthPkiGroupCache = QMap<QString, QgsAuthPkiGroup *>();

QgsAuthenticationManager *QgsAuthenticationManager::instance()
{
    if ( !smInstance )
    {
      smInstance = new QgsAuthenticationManager();
    }
    return smInstance;
}

bool QgsAuthenticationManager::queryDb( const QString& query, QSqlDatabase db )
{
  QSqlQuery ret = db.exec( query );
  if ( ret.lastError().isValid() )
  {
    emit messageOut( ret.lastError().text(), "", CRITICAL );
    db.close();
    return false;
  }
  return true;
}

bool QgsAuthenticationManager::initAuthDatabase()
{
  QFileInfo dbinfo( QgsApplication::qgisAuthDbFilePath() );
  if ( dbinfo.exists() )
  {
    if ( !dbinfo.permission( QFile::ReadOwner | QFile::WriteOwner ) )
    {
      emit messageOut( "Authentication database is not readable or writable by user",
                       "", CRITICAL );
      return false;
    }
    if ( dbinfo.size() > 0 )
    {
      emit messageOut( "Authentication database exists and has data" );
      return true;
    }
  }

  // create the database
  QSqlDatabase authdb( QSqlDatabase::addDatabase( "QSQLITE" ) );
  authdb.setDatabaseName( dbinfo.absoluteFilePath() );
  if ( !authdb.open() ) {
      emit messageOut( "Unable to establish authentication database connection",
                       "", CRITICAL );
      return false;
  }
  QString query;
  query += "CREATE TABLE auth_configs (\n";
  query += "    \"id\" TEXT NOT NULL,\n";
  query += "    \"name\" TEXT NOT NULL,\n";
  query += "    \"uri\" TEXT,\n";
  query += "    \"type\" INTEGER NOT NULL,\n";
  query += "    \"version\" INTEGER NOT NULL\n";
  query += ", \"config\" TEXT  NOT NULL);";
  if ( !queryDb( query, authdb ) )
    return false;
  query = "CREATE UNIQUE INDEX \"id_index\" on auth_configs (id ASC);";
  if ( !queryDb( query, authdb ) )
    return false;
  query = "CREATE INDEX \"uri_index\" on auth_configs (uri ASC);";
  if ( !queryDb( query, authdb ) )
    return false;

  authdb.close();
  return true;
}

void QgsAuthenticationManager::writeDebug(const QString &message,
                                          const QString &tag,
                                          MessageLevel level)
{
  QString msg;
  switch ( level )
  {
    case INFO:
      break;
    case WARNING:
      msg += "WARNING: ";
      break;
    case CRITICAL:
      msg += "ERROR: ";
      break;
    default:
      break;
  }

  if ( !tag.isEmpty() )
  {
    msg += QString( "( %1 ) " ).arg( tag );
  }

  msg += message;
  qDebug( "%s", msg.toLatin1().constData() );
}

QgsAuthenticationManager::QgsAuthenticationManager( QObject *parent )
  : QObject( parent )
{
  connect( this, SIGNAL( messageOut( const QString&, const QString&, MessageLevel ) ),
           this, SLOT( writeDebug( const QString&, const QString&, MessageLevel ) ) );
}

QgsAuthenticationManager::~QgsAuthenticationManager()
{

}

//const QString QgsAuthenticationManager::authDbConnection() const
//{

//}
