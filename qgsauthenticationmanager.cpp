#include "qgsauthenticationmanager.h"

#include <QFileInfo>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QVariant>

#include "qgsapplication.h"
#include "qgscredentials.h"


QgsAuthenticationManager *QgsAuthenticationManager::smInstance = 0;
//QMap<QString, QgsAuthPkiGroup *> QgsAuthenticationManager::mAuthPkiGroupCache = QMap<QString, QgsAuthPkiGroup *>();
const QString QgsAuthenticationManager::smAuthConfigTable = "auth_configs";

QgsAuthenticationManager *QgsAuthenticationManager::instance()
{
    if ( !smInstance )
    {
      smInstance = new QgsAuthenticationManager();
    }
    return smInstance;
}

QSqlDatabase QgsAuthenticationManager::authDbConnection() const
{
  QSqlDatabase authdb;
  QString connectionname = "authentication.configs";
  if ( !QSqlDatabase::contains( connectionname ) )
  {
    authdb = QSqlDatabase::addDatabase( "QSQLITE", connectionname );
    authdb.setDatabaseName( QgsApplication::qgisAuthDbFilePath() );
  }
  else
  {
    authdb = QSqlDatabase::database( connectionname );
  }
  return authdb;
}

bool QgsAuthenticationManager::initAuthDatabase() const
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
  bool qok = false;
  QString query;
  query += QString( "CREATE TABLE %1 (\n" ).arg( authDbTable() );
  query += "    'id' TEXT NOT NULL,\n";
  query += "    'name' TEXT NOT NULL,\n";
  query += "    'uri' TEXT,\n";
  query += "    'type' INTEGER NOT NULL,\n";
  query += "    'version' INTEGER NOT NULL\n";
  query += ", 'config' TEXT  NOT NULL);";

  queryAuthDb( query, &qok );
  if ( !qok )
    return false;
  query = QString( "CREATE UNIQUE INDEX 'id_index' on %1 (id ASC);" ).arg( authDbTable() );
  queryAuthDb( query, &qok );
  if ( !qok )
    return false;
  query = QString( "CREATE INDEX 'uri_index' on %1 (uri ASC);" ).arg( authDbTable() );
  queryAuthDb( query, &qok );
  if ( !qok )
    return false;

  authDbConnection().close();

  return true;
}

const QString QgsAuthenticationManager::uniqueConfigId() const
{
  return QString();
}

bool QgsAuthenticationManager::configIdUnique( const QString& id ) const
{
  QStringList configids = configIds();
  return configids.contains( id );
}

void QgsAuthenticationManager::inputMasterPassword()
{
  QString pass;
  QgsCredentials * creds = QgsCredentials::instance();
  creds->lock();
  // TODO: validate in actual QgsCredentials input methods that password is not empty
  bool ok = creds->getMasterPassword( &pass );
  creds->unlock();
  if ( !ok )
  {
    emit messageOut( "Master password input canceled by user" );
    return;
  }
  if ( mMasterPass != pass && !pass.isEmpty() )
  {
    mMasterPass = pass;
  }
}

bool QgsAuthenticationManager::resetMasterPassword()
{
  return true;
}

const QString QgsAuthenticationManager::generateConfigId() const
{
  int len = 7;
  QString id = "";
  for( int i=0; i < len; i++ )
  {
    switch( qrand() % 2 )
    {
      case 0:
          id += ( '0' + qrand() % 10 );
          break;
      case 1:
          id += ( 'a' + qrand() % 26 );
          break;
    }
  }
  return id;
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
  , mMasterPass( "" )
{
  connect( this, SIGNAL( messageOut( const QString&, const QString&, MessageLevel ) ),
           this, SLOT( writeDebug( const QString&, const QString&, MessageLevel ) ) );
}

QgsAuthenticationManager::~QgsAuthenticationManager()
{

}

QStringList QgsAuthenticationManager::configIds() const
{
  QStringList configids = QStringList();

  bool qok = false;
  QString query = QString( "SELECT id FROM %1" ).arg( authDbTable() );
  QSqlQuery qres = queryAuthDb( query, &qok );
  if ( !qok )
    return configids;
  if ( qres.isActive() )
  {
    while ( qres.next() )
    {
       configids << qres.value(0).toString();
    }
  }
  return configids;
}

QSqlQuery QgsAuthenticationManager::queryAuthDb( const QString& query, bool *ok ) const
{
  QSqlDatabase authdb = authDbConnection();
  if ( !authdb.isOpen() )
  {
    if ( !authdb.open() ) {
        emit messageOut( tr( "Unable to establish database connection\nDatabase: %1\nDriver error: %2\nDatabase error: %3" )
                         .arg( QgsApplication::qgisAuthDbFilePath() )
                         .arg( authdb.lastError().driverText() )
                         .arg( authdb.lastError().databaseText() ),
                         "", CRITICAL );
        *ok = false;
    }
  }

  QSqlQuery q = QSqlQuery( authdb );
  q.setForwardOnly( true );
  q.exec( query );

  if ( q.lastError().isValid() )
  {
    emit messageOut( tr( "Database query failed: %1").arg( q.lastError().text() ), "", CRITICAL );
    *ok = false;
  }
  *ok = true;
  return q;
}

