#include "qgsauthenticationmanager.h"

#include <QFileInfo>
#include <QObject>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QTime>
#include <QVariant>

#include "qgsapplication.h"
#include "qgsauthenticationcrypto.h"
#include "qgscredentials.h"


QgsAuthManager *QgsAuthManager::smInstance = 0;
//QMap<QString, QgsAuthPkiGroup *> QgsAuthManager::mAuthPkiGroupCache = QMap<QString, QgsAuthPkiGroup *>();
const QString QgsAuthManager::smAuthConfigTable = "auth_configs";
const QString QgsAuthManager::smAuthPassTable = "auth_pass";
const QString QgsAuthManager::smAuthManTag = QObject::tr( "Authentication Manager" );

QgsAuthManager *QgsAuthManager::instance()
{
  if ( !smInstance )
  {
    smInstance = new QgsAuthManager();
  }
  return smInstance;
}

QSqlDatabase QgsAuthManager::authDbConnection() const
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
  if ( !authdb.isOpen() )
    authdb.open();

  return authdb;
}

bool QgsAuthManager::init()
{
  QFileInfo dbinfo( QgsApplication::qgisAuthDbFilePath() );
  if ( dbinfo.exists() )
  {
    if ( !dbinfo.permission( QFile::ReadOwner | QFile::WriteOwner ) )
    {
      emit messageOut( tr( "Auth db is not readable or writable by user" ),
                       authManTag(), CRITICAL );
      return false;
    }
    if ( dbinfo.size() > 0 )
    {
      emit messageOut( "Auth db exists and has data" );
      updateConfigProviderTypes();
      return true;
    }
  }

  // create and open the db
  if ( !authDbOpen() )
  {
    emit messageOut( tr( "Auth db could not be created and opened" ),
                     authManTag(), CRITICAL );
    return false;
  }

  QSqlQuery query( authDbConnection() );

  // create the tables
  QString qstr;

  qstr = QString( "CREATE TABLE %1 (\n"
                  "    'salt' TEXT NOT NULL\n"
                  ", 'hash' TEXT  NOT NULL);" ).arg( authDbPassTable() );
  query.prepare( qstr );
  if ( !authDbQuery( &query ) )
    return false;
  query.clear();

  qstr = QString( "CREATE TABLE %1 (\n"
                  "    'id' TEXT NOT NULL,\n"
                  "    'name' TEXT NOT NULL,\n"
                  "    'uri' TEXT,\n"
                  "    'type' TEXT NOT NULL,\n"
                  "    'version' INTEGER NOT NULL\n"
                  ", 'config' TEXT  NOT NULL);" ).arg( authDbConfigTable() );
  query.prepare( qstr );
  if ( !authDbQuery( &query ) )
    return false;
  query.clear();

  qstr = QString( "CREATE UNIQUE INDEX 'id_index' on %1 (id ASC);" ).arg( authDbConfigTable() );
  query.prepare( qstr );
  if ( !authDbQuery( &query ) )
    return false;
  query.clear();

  qstr = QString( "CREATE INDEX 'uri_index' on %1 (uri ASC);" ).arg( authDbConfigTable() );
  query.prepare( qstr );
  if ( !authDbQuery( &query ) )
    return false;
  query.clear();

  return true;
}

bool QgsAuthManager::setMasterPassword( bool verify )
{
  if ( mMasterPass.isEmpty() )
  {
    emit messageOut( "Master password: not yet set by user" );
    if ( !masterPasswordInput() )
    {
      emit messageOut( "Master password: input canceled by user" );
      return false;
    }
  }
  else
  {
    emit messageOut( "Master password: is set" );
    if ( !verify )
      return true;
  }

  int rows = 0;
  if ( !masterPasswordRowsInDb( &rows ) )
  {
    emit messageOut( tr( "Master password: FAILED to access auth db" ),
                     authManTag(), CRITICAL );
    clearMasterPassword();
    return false;
  }

  emit messageOut( QString( "Master password: %1 rows in auth db" ).arg( rows ) );

  if ( rows > 1 )
  {
    emit messageOut( tr( "Master password: FAILED to find just one master password record in auth db" ),
                     authManTag(), CRITICAL );
    clearMasterPassword();
    return false;
  }
  else if ( rows == 1 )
  {
    if ( !masterPasswordCheckAgainstDb() )
    {
      emit messageOut( tr( "Master password: FAILED to verify against hash in auth db" ),
                       authManTag(), CRITICAL );
      clearMasterPassword();
      emit masterPasswordVerified( false );
      return false;
    }
    else
    {
      emit messageOut( "Master password: verified against hash in auth db" );
      emit masterPasswordVerified( true );
    }
  }
  else
  {
    if ( !masterPasswordStoreInDb() )
    {
      emit messageOut( tr( "Master password: hash FAILED to be stored in auth db" ),
                       authManTag(), CRITICAL );
      clearMasterPassword();
      return false;
    }
    else
    {
      emit messageOut( "Master password: hash stored in auth db" );
    }
    // double-check storing
    if ( !masterPasswordCheckAgainstDb() )
    {
      emit messageOut( tr( "Master password: FAILED to verify against hash in auth db" ),
                       authManTag(), CRITICAL );
      clearMasterPassword();
      emit masterPasswordVerified( false );
      return false;
    }
    else
    {
      emit messageOut( "Master password: verified against hash in auth db" );
      emit masterPasswordVerified( true );
    }
  }

  emit messageOut( "Master password: SUCCESS, verified and ready" );
  return true;
}

bool QgsAuthManager::masterPasswordIsSet() const
{
  return !mMasterPass.isEmpty();
}

bool QgsAuthManager::masterPasswordSame( const QString &pass ) const
{
  return mMasterPass == pass;
}

bool QgsAuthManager::resetMasterPassword()
{
  // TODO: add master password reset

  // check that a master password is even set in auth db, if not offer to set one

  // get new password
  masterPasswordResetInput();

  // duplicate current db file to 'new'

  // create new connection

  // loop through available configs and decrypt, then re-encrypt with new password

  //   get encrypted config and decrypt

  //   re-encrypt with new password

  //   update db record

  // dump old password

  // insert new password


  // --- on success at this point ---

  // close current connection to old db

  // back up current db to .bkup

  // rename new to current name

  // reopen connection and verify new name

  // read and decrypt a config, to test?

  return true;
}

void QgsAuthManager::registerProviders()
{
  mProviders.insert( QgsAuthType::Basic, new QgsAuthProviderBasic() );
#ifndef QT_NO_OPENSSL
  mProviders.insert( QgsAuthType::PkiPaths, new QgsAuthProviderPkiPaths() );
#endif
}

const QString QgsAuthManager::uniqueConfigId() const
{
  QStringList configids = configIds();
  QString id;
  int len = 7;
  uint seed = ( uint ) QTime::currentTime().msec();
  qsrand( seed );

  while ( true )
  {
    id = "";
    for ( int i = 0; i < len; i++ )
    {
      switch ( qrand() % 2 )
      {
        case 0:
          id += ( '0' + qrand() % 10 );
          break;
        case 1:
          id += ( 'a' + qrand() % 26 );
          break;
      }
    }
    if ( !configids.contains( id ) )
    {
      break;
    }
  }
  emit messageOut( QString( "Generated unique ID: %1" ).arg( id ) );
  return id;
}

bool QgsAuthManager::configIdUnique( const QString& id ) const
{
  if ( id.isEmpty() )
  {
    emit messageOut( "Config ID is empty", authManTag(), WARNING );
    return false;
  }
  QStringList configids = configIds();
  return !configids.contains( id );
}

QHash<QString, QgsAuthConfigBase> QgsAuthManager::availableConfigs()
{
  QHash<QString, QgsAuthConfigBase> baseConfigs;

  QSqlQuery query( authDbConnection() );
  query.prepare( QString( "SELECT id, name, uri, type, version FROM %1" ).arg( authDbConfigTable() ) );

  if ( !authDbQuery( &query ) )
  {
    return baseConfigs;
  }

  if ( query.isActive() && query.isSelect() )
  {
    while ( query.next() )
    {
      QString authid = query.value( 0 ).toString();
      QgsAuthConfigBase config;
      config.setId( authid );
      config.setName( query.value( 1 ).toString() );
      config.setUri( query.value( 2 ).toString() );
      config.setType( QgsAuthType::stringToType( query.value( 3 ).toString() ) );
      config.setVersion( query.value( 4 ).toInt() );

      baseConfigs.insert( authid, config );
    }
  }
  return baseConfigs;
}

void QgsAuthManager::updateConfigProviderTypes()
{
  QSqlQuery query( authDbConnection() );
  query.prepare( QString( "SELECT id, type FROM %1" ).arg( authDbConfigTable() ) );

  if ( !authDbQuery( &query ) )
  {
    return;
  }

  if ( query.isActive() )
  {
    emit messageOut( "Synching existing auth config provider types" );
    mConfigProviders.clear();
    while ( query.next() )
    {
      mConfigProviders.insert( query.value( 0 ).toString(),
                               QgsAuthType::stringToType( query.value( 1 ).toString() ) );
    }
  }
}

QgsAuthProvider* QgsAuthManager::configProvider( const QString& authid )
{
  if ( !mConfigProviders.contains( authid ) )
    return 0;

  QgsAuthType::ProviderType ptype = mConfigProviders.value( authid );

  if ( ptype == QgsAuthType::None || ptype == QgsAuthType::Unknown )
    return 0;

  return mProviders.value( ptype );
}

QgsAuthType::ProviderType QgsAuthManager::configProviderType( const QString& authid )
{
  if ( !mConfigProviders.contains( authid ) )
    return QgsAuthType::Unknown;

  return mConfigProviders.value( authid );
}

bool QgsAuthManager::storeAuthenticationConfig( QgsAuthConfigBase &config )
{
  if ( !setMasterPassword( true ) )
    return false;

  // don't need to validate id, since it has not be defined yet
  if ( !config.isValid() )
  {
    emit messageOut( tr( "Store config: FAILED because config is invalid" ),
                     authManTag(), CRITICAL );
    return false;
  }

  QString configstring = config.configString();
  if ( configstring.isEmpty() )
  {
    emit messageOut( tr( "Store config: FAILED because config is empty" ),
                     authManTag(), CRITICAL );
    return false;
  }
#if( 0 )
  emit messageOut( QString( "authDbConfigTable(): %1" ).arg( authDbConfigTable() ) );
  emit messageOut( QString( "name: %1" ).arg( config.name() ) );
  emit messageOut( QString( "uri: %1" ).arg( config.uri() ) );
  emit messageOut( QString( "type: %1" ).arg( config.typeToString() ) );
  emit messageOut( QString( "version: %1" ).arg( config.version() ) );
  emit messageOut( QString( "config: %1" ).arg( configstring ) ); // DO NOT LEAVE THIS LINE UNCOMMENTED !
#endif

  QSqlQuery query( authDbConnection() );
  query.prepare( QString( "INSERT INTO %1 (id, name, uri, type, version, config) "
                          "VALUES (:id, :name, :uri, :type, :version, :config)" ).arg( authDbConfigTable() ) );

  QString uid = uniqueConfigId();

  query.bindValue( ":id", uid );
  query.bindValue( ":name", config.name() );
  query.bindValue( ":uri", config.uri() );
  query.bindValue( ":type", config.typeToString() );
  query.bindValue( ":version", config.version() );
  query.bindValue( ":config", QgsAuthCrypto::encrypt( mMasterPass, configstring, "AES" ) );

  if ( !authDbStartTransaction() )
    return false;

  if ( !authDbQuery( &query ) )
    return false;

  if ( !authDbCommit() )
    return false;

  // passed-in config should now be like as if it was just loaded from db
  config.setId( uid );

  updateConfigProviderTypes();

  emit messageOut( QString( "Store config SUCCESS for authid: %1" ).arg( uid ) );
  return true;
}

bool QgsAuthManager::updateAuthenticationConfig( const QgsAuthConfigBase& config )
{
  if ( !setMasterPassword( true ) )
    return false;

  // validate id
  if ( !config.isValid( true ) )
  {
    emit messageOut( tr( "Update config: FAILED because config is invalid" ),
                     authManTag(), CRITICAL );
    return false;
  }

  QString configstring = config.configString();
  if ( configstring.isEmpty() )
  {
    emit messageOut( tr( "Update config: FAILED because config is empty" ),
                     authManTag(), CRITICAL );
    return false;
  }

#if( 0 )
  emit messageOut( QString( "authDbConfigTable(): %1" ).arg( authDbConfigTable() ) );
  emit messageOut( QString( "id: %1" ).arg( config.id() ) );
  emit messageOut( QString( "name: %1" ).arg( config.name() ) );
  emit messageOut( QString( "uri: %1" ).arg( config.uri() ) );
  emit messageOut( QString( "type: %1" ).arg( config.typeToString() ) );
  emit messageOut( QString( "version: %1" ).arg( config.version() ) );
  emit messageOut( QString( "config: %1" ).arg( configstring ) ); // DO NOT LEAVE THIS LINE UNCOMMENTED !
#endif

  QSqlQuery query( authDbConnection() );
  if ( !query.prepare( QString( "UPDATE %1 "
                                "SET name = :name, uri = :uri, type = :type, version = :version, config = :config "
                                "WHERE id = :id" ).arg( authDbConfigTable() ) ) )
  {
    emit messageOut( tr( "Update config: FAILED to prepare query" ),
                     authManTag(), CRITICAL );
    return false;
  }

  query.bindValue( ":id", config.id() );
  query.bindValue( ":name", config.name() );
  query.bindValue( ":uri", config.uri() );
  query.bindValue( ":type", config.typeToString() );
  query.bindValue( ":version", config.version() );
  query.bindValue( ":config", QgsAuthCrypto::encrypt( mMasterPass, configstring, "AES" ) );

  if ( !authDbStartTransaction() )
    return false;

  if ( !authDbQuery( &query ) )
    return false;

  if ( !authDbCommit() )
    return false;

  updateConfigProviderTypes();

  emit messageOut( QString( "Update config SUCCESS for authid: %1" ).arg( config.id() ) );

  return true;
}

bool QgsAuthManager::loadAuthenticationConfig( const QString& authid, QgsAuthConfigBase &config, bool full )
{
  if ( full && !setMasterPassword( true ) )
    return false;

  QSqlQuery query( authDbConnection() );
  full = full && config.type() != QgsAuthType::None; // negates 'full' if loading into base class
  if ( full )
  {
    query.prepare( QString( "SELECT id, name, uri, type, version, config FROM %1 "
                            "WHERE id = :id" ).arg( authDbConfigTable() ) );
  }
  else
  {
    query.prepare( QString( "SELECT id, name, uri, type, version FROM %1 "
                            "WHERE id = :id" ).arg( authDbConfigTable() ) );
  }

  query.bindValue( ":id", authid );

  if ( !authDbQuery( &query ) )
  {
    return false;
  }

  if ( query.isActive() && query.isSelect() )
  {
    if ( query.first() )
    {
      config.setId( query.value( 0 ).toString() );
      config.setName( query.value( 1 ).toString() );
      config.setUri( query.value( 2 ).toString() );
      config.setType( QgsAuthType::stringToType( query.value( 3 ).toString() ) );
      config.setVersion( query.value( 4 ).toInt() );

      if ( full )
      {
        config.loadConfigString( QgsAuthCrypto::decrypt( mMasterPass, query.value( 5 ).toString(), "AES" ) );
      }

      emit messageOut( QString( "Load %1 config SUCCESS for authid: %2" ).arg( full ? "full" : "base" ) .arg( authid ) );
      return true;
    }
    if ( query.next() )
    {
      emit messageOut( QString( "Select contains more than one for authid: %1" ).arg( authid ),
                       authManTag(), WARNING );
    }
  }
  return false;
}

bool QgsAuthManager::removeAuthenticationConfig( const QString& authid )
{
  if ( authid.isEmpty() )
    return false;

  QSqlQuery query( authDbConnection() );

  query.prepare( QString( "DELETE FROM %1 WHERE id = :id" ).arg( authDbConfigTable() ) );

  query.bindValue( ":id", authid );

  if ( !authDbStartTransaction() )
    return false;

  if ( !authDbQuery( &query ) )
    return false;

  if ( !authDbCommit() )
    return false;

  updateConfigProviderTypes();

  emit messageOut( QString( "REMOVED config for authid: %1" ).arg( authid ) );

  return true;
}

void QgsAuthManager::updateNetworkRequest( QNetworkRequest &request, const QString& authid )
{
  QgsAuthProvider* provider = configProvider( authid );
  if ( provider )
  {
    provider->updateNetworkRequest( request, authid );
  }
}

void QgsAuthManager::updateNetworkReply( QNetworkReply *reply, const QString& authid )
{
  QgsAuthProvider* provider = configProvider( authid );
  if ( provider )
  {
    provider->updateNetworkReply( reply , authid );
  }
}

void QgsAuthManager::writeDebug( const QString &message,
                                 const QString &tag,
                                 MessageLevel level )
{
  Q_UNUSED( tag );

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

//  if ( !tag.isEmpty() )
//  {
//    msg += QString( "( %1 ) " ).arg( tag );
//  }

  msg += message;
  qDebug( "%s", msg.toLatin1().constData() );
}

QgsAuthManager::QgsAuthManager( QObject *parent )
    : QObject( parent )
    , mMasterPass( QString() )
    , mMasterPassReset( QString() )
{
  connect( this, SIGNAL( messageOut( const QString&, const QString&, MessageLevel ) ),
           this, SLOT( writeDebug( const QString&, const QString&, MessageLevel ) ) );
}

QgsAuthManager::~QgsAuthManager()
{
  qDeleteAll( mProviders.values() );
}

bool QgsAuthManager::masterPasswordInput()
{
  QString pass;
  QgsCredentials * creds = QgsCredentials::instance();
  creds->lock();
  // TODO: validate in actual QgsCredentials input methods that password is not empty
  bool ok = creds->getMasterPassword( &pass );
  creds->unlock();

  if ( ok && !pass.isEmpty() && !masterPasswordSame( pass ) )
  {
    mMasterPass = pass;
    return true;
  }
  return false;
}

bool QgsAuthManager::masterPasswordResetInput()
{
  QString pass;
  QgsCredentials * creds = QgsCredentials::instance();
  creds->lock();
  // TODO: validate in actual QgsCredentials input methods that password is not empty
  bool ok = creds->getMasterResetPassword( &pass );
  creds->unlock();

  if ( ok && !pass.isEmpty() && !masterPasswordSame( pass ) )
  {
    mMasterPassReset = pass;
    return true;
  }
  return false;
}

bool QgsAuthManager::masterPasswordRowsInDb( int *rows ) const
{
  QSqlQuery query( authDbConnection() );
  query.prepare( QString( "SELECT Count(*) FROM %1" ).arg( authDbPassTable() ) );

  bool ok = authDbQuery( &query );
  if ( query.first() )
  {
    *rows = query.value( 0 ).toInt();
  }

  query.clear();
  return ok;
}

bool QgsAuthManager::masterPasswordCheckAgainstDb() const
{
  // first verify there is only one row in auth db (uses first found)

  QSqlQuery query( authDbConnection() );
  query.prepare( QString( "SELECT salt, hash FROM %1" ).arg( authDbPassTable() ) );
  if ( !authDbQuery( &query ) )
    return false;

  if ( !query.first() )
    return false;

  QString salt = query.value( 0 ).toString();
  QString hash = query.value( 1 ).toString();

  query.clear();

  return QgsAuthCrypto::verifyPasswordHash( mMasterPass, salt, hash );
}

bool QgsAuthManager::masterPasswordStoreInDb() const
{
  QString salt, hash;
  QgsAuthCrypto::passwordHash( mMasterPass, &salt, &hash );

  QSqlQuery query( authDbConnection() );
  query.prepare( QString( "INSERT INTO %1 (salt, hash) VALUES (:salt, :hash)" ).arg( authDbPassTable() ) );

  query.bindValue( ":salt", salt );
  query.bindValue( ":hash", hash );

  if ( !authDbStartTransaction() )
    return false;

  if ( !authDbQuery( &query ) )
    return false;

  if ( !authDbCommit() )
    return false;

  return true;
}

bool QgsAuthManager::masterPasswordClearDb() const
{
  QSqlQuery query( authDbConnection() );
  query.prepare( QString( "DELETE FROM %1" ).arg( authDbPassTable() ) );
  return authDbTransactionQuery( &query );
}

QStringList QgsAuthManager::configIds() const
{
  QStringList configids = QStringList();

  QSqlQuery query( authDbConnection() );
  query.prepare( QString( "SELECT id FROM %1" ).arg( authDbConfigTable() ) );

  if ( !authDbQuery( &query ) )
  {
    return configids;
  }

  if ( query.isActive() )
  {
    while ( query.next() )
    {
      configids << query.value( 0 ).toString();
    }
  }
  return configids;
}

bool QgsAuthManager::authDbOpen() const
{
  QSqlDatabase authdb = authDbConnection();
  if ( !authdb.isOpen() )
  {
    if ( !authdb.open() )
    {
      emit messageOut( tr( "Unable to establish database connection\nDatabase: %1\nDriver error: %2\nDatabase error: %3" )
                       .arg( QgsApplication::qgisAuthDbFilePath() )
                       .arg( authdb.lastError().driverText() )
                       .arg( authdb.lastError().databaseText() ),
                       authManTag(), CRITICAL );
      return false;
    }
  }
  return true;
}

bool QgsAuthManager::authDbQuery( QSqlQuery *query ) const
{

  query->setForwardOnly( true );
  query->exec();

  if ( query->lastError().isValid() )
  {
    emit messageOut( tr( "Auth db query FAILED: %1" ).arg( query->executedQuery() ), authManTag(), CRITICAL );
    emit messageOut( tr( "Error: %1" ).arg( query->lastError().text() ), authManTag(), CRITICAL );
    return false;
  }

  return true;
}

bool QgsAuthManager::authDbStartTransaction() const
{
  if ( !authDbConnection().transaction() )
  {
    emit messageOut( tr( "Auth db FAILED to start transaction" ), authManTag(), CRITICAL );
    return false;
  }

  return true;
}

bool QgsAuthManager::authDbCommit() const
{
  if ( !authDbConnection().commit() )
  {
    emit messageOut( tr( "Auth db FAILED to rollback changes" ), authManTag(), CRITICAL );
    authDbConnection().rollback();
    return false;
  }

  return true;
}

bool QgsAuthManager::authDbTransactionQuery( QSqlQuery *query ) const
{
  if ( !authDbConnection().transaction() )
  {
    emit messageOut( tr( "Auth db FAILED to start transaction" ), authManTag(), CRITICAL );
    return false;
  }

  bool ok = authDbQuery( query );

  if ( ok && !authDbConnection().commit() )
  {
    emit messageOut( tr( "Auth db FAILED to rollback changes" ), authManTag(), CRITICAL );
    authDbConnection().rollback();
    return false;
  }

  return ok;
}

