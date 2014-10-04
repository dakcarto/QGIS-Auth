#include "qgsauthenticationconfig.h"

#include "qgsauthenticationmanager.h"
#include "qgsauthenticationprovider.h"

#include <QObject>

const QString QgsAuthenticationConfigBase::mConfSep = "|||";

// get uniqueConfigId only on save
QgsAuthenticationConfigBase::QgsAuthenticationConfigBase( ProviderType type, int version )
    : mId( QString() )
    , mName( QString() )
    , mUri( QString() )
    , mType( type )
    , mVersion( version )
{
}

QgsAuthenticationConfigBase::QgsAuthenticationConfigBase( const QgsAuthenticationConfigBase &config )
    : mId( config.id() )
    , mName( config.name() )
    , mUri( config.uri() )
    , mType( config.type() )
    , mVersion( config.version() )
{
}

const QString QgsAuthenticationConfigBase::typeAsString() const
{
  return QgsAuthenticationProvider::typeAsString( mType );
}

bool QgsAuthenticationConfigBase::isValid( bool validateid ) const
{
  bool idvalid = true;
  if ( validateid )
  {
    idvalid = !mId.isEmpty() && QgsAuthenticationManager::instance()->configIdUnique( mId );
  }
  return (
           idvalid
           && !mName.isEmpty()
           && !mUri.isEmpty()
           && mType != QgsAuthenticationConfigBase::Unknown
           && mVersion != 0
         );
}

const QgsAuthenticationConfigBase QgsAuthenticationConfigBase::toBaseConfig()
{
  return QgsAuthenticationConfigBase( *this );
}


//////////////////////////////////////////////////////////////////////////////
/// QgsAuthenticationConfigBasic
//////////////////////////////////////////////////////////////////////////////

QgsAuthenticationConfigBasic::QgsAuthenticationConfigBasic()
    : QgsAuthenticationConfigBase( QgsAuthenticationConfigBase::Basic, 1 )
    , mRealm( QString() )
    , mUsername( QString() )
    , mPassword( QString() )
{
}

bool QgsAuthenticationConfigBasic::isValid( bool validateid ) const
{
  // password can be empty
  return (
           QgsAuthenticationConfigBase::isValid( validateid )
           && !mRealm.isEmpty()
           && !mUsername.isEmpty()
         );
}

const QString QgsAuthenticationConfigBasic::configString() const
{
  QStringList configlist = QStringList() << mRealm << mUsername << mPassword;
  return configlist.join( mConfSep );
}

void QgsAuthenticationConfigBasic::loadConfigString( const QString& config )
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
/// QgsAuthenticationConfigPki
//////////////////////////////////////////////////////////////////////////////

QgsAuthenticationConfigPkiPaths::QgsAuthenticationConfigPkiPaths()
    : QgsAuthenticationConfigBase( QgsAuthenticationConfigBase::PkiPaths, 1 )
    , mCertId( QString() )
    , mKeyId( QString() )
    , mKeyPass( QString() )
    , mIssuerId( QString() )
    , mIssuerSelf( false )
{
}

bool QgsAuthenticationConfigPkiPaths::isValid( bool validateid ) const
{
  return (
           QgsAuthenticationConfigBase::isValid( validateid )
           && !mCertId.isEmpty()
           && !mKeyId.isEmpty()
         );
}

const QString QgsAuthenticationConfigPkiPaths::configString() const
{
  QStringList configlist = QStringList();
  configlist << mCertId << mKeyId << mKeyPass << mIssuerId << QString::number( mIssuerSelf );
  return configlist.join( mConfSep );
}

void QgsAuthenticationConfigPkiPaths::loadConfigString( const QString& config )
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
