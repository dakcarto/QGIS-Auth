#include "qgsauthenticationconfig.h"

#include "qgsauthenticationmanager.h"
#include "qgsauthenticationprovider.h"

#include <QObject>

const QString QgsAuthConfigBase::mConfSep = "|||";

// get uniqueConfigId only on save
QgsAuthConfigBase::QgsAuthConfigBase( ProviderType type, int version )
    : mId( QString() )
    , mName( QString() )
    , mUri( QString() )
    , mType( type )
    , mVersion( version )
{
}

QgsAuthConfigBase::QgsAuthConfigBase( const QgsAuthConfigBase &config )
    : mId( config.id() )
    , mName( config.name() )
    , mUri( config.uri() )
    , mType( config.type() )
    , mVersion( config.version() )
{
}

const QString QgsAuthConfigBase::typeAsString() const
{
  return QgsAuthProvider::typeAsString( mType );
}

bool QgsAuthConfigBase::isValid( bool validateid ) const
{
  bool idvalid = true;
  if ( validateid )
  {
    idvalid = !mId.isEmpty() && QgsAuthManager::instance()->configIdUnique( mId );
  }
  return (
           idvalid
           && !mName.isEmpty()
           && !mUri.isEmpty()
           && mType != QgsAuthConfigBase::Unknown
           && mVersion != 0
         );
}

const QgsAuthConfigBase QgsAuthConfigBase::toBaseConfig()
{
  return QgsAuthConfigBase( *this );
}


//////////////////////////////////////////////////////////////////////////////
/// QgsAuthConfigBasic
//////////////////////////////////////////////////////////////////////////////

QgsAuthConfigBasic::QgsAuthConfigBasic()
    : QgsAuthConfigBase( QgsAuthConfigBase::Basic, 1 )
    , mRealm( QString() )
    , mUsername( QString() )
    , mPassword( QString() )
{
}

bool QgsAuthConfigBasic::isValid( bool validateid ) const
{
  // password can be empty
  return (
           QgsAuthConfigBase::isValid( validateid )
           && !mRealm.isEmpty()
           && !mUsername.isEmpty()
         );
}

const QString QgsAuthConfigBasic::configString() const
{
  QStringList configlist = QStringList() << mRealm << mUsername << mPassword;
  return configlist.join( mConfSep );
}

void QgsAuthConfigBasic::loadConfigString( const QString& config )
{
  if ( config.isEmpty() )
  {
    return;
  }
  QStringList configlist = config.split( mConfSep );
  mRealm = configlist.at( 0 );
  mUsername = configlist.at( 1 );
  mPassword = configlist.at( 2 );
}

//////////////////////////////////////////////////////////////////////////////
/// QgsAuthConfigPki
//////////////////////////////////////////////////////////////////////////////

QgsAuthConfigPkiPaths::QgsAuthConfigPkiPaths()
    : QgsAuthConfigBase( QgsAuthConfigBase::PkiPaths, 1 )
    , mCertId( QString() )
    , mKeyId( QString() )
    , mKeyPass( QString() )
    , mIssuerId( QString() )
    , mIssuerSelf( false )
{
}

bool QgsAuthConfigPkiPaths::isValid( bool validateid ) const
{
  return (
           QgsAuthConfigBase::isValid( validateid )
           && !mCertId.isEmpty()
           && !mKeyId.isEmpty()
         );
}

const QString QgsAuthConfigPkiPaths::configString() const
{
  QStringList configlist = QStringList();
  configlist << mCertId << mKeyId << mKeyPass << mIssuerId << QString::number( mIssuerSelf );
  return configlist.join( mConfSep );
}

void QgsAuthConfigPkiPaths::loadConfigString( const QString& config )
{
  if ( config.isEmpty() )
  {
    return;
  }
  QStringList configlist = config.split( mConfSep );
  mCertId = configlist.at( 0 );
  mKeyId = configlist.at( 1 );
  mKeyPass = configlist.at( 2 );
  mIssuerId = configlist.at( 3 );
  mIssuerSelf = ( bool ) configlist.at( 4 ).toInt();
}
