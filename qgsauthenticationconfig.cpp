#include "qgsauthenticationconfig.h"

#include "qgsauthenticationmanager.h"
#include "qgsauthenticationprovider.h"

#include <QObject>

const QString QgsAuthenticationConfigBase::mConfSep = "|||";

// get uniqueConfigId only on save
QgsAuthenticationConfigBase::QgsAuthenticationConfigBase( QgsAuthenticationProvider::ProviderType type, int version )
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

bool QgsAuthenticationConfigBase::isValid() const
{
  return (
           !mId.isEmpty()
           && QgsAuthenticationManager::instance()->configIdUnique( mId )
           && !mName.isEmpty()
           && !mUri.isEmpty()
           && mType != QgsAuthenticationProvider::Unknown
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
    : QgsAuthenticationConfigBase( QgsAuthenticationProvider::Basic, 1 )
    , mRealm( QString() )
    , mUsername( QString() )
    , mPassword( QString() )
{
}

bool QgsAuthenticationConfigBasic::isValid() const
{
  // password can be empty
  return (
           QgsAuthenticationConfigBase::isValid()
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

QgsAuthenticationConfigPki::QgsAuthenticationConfigPki()
    : QgsAuthenticationConfigBase( QgsAuthenticationProvider::PkiPaths, 1 )
    , mCertId( QString() )
    , mKeyId( QString() )
    , mKeyPass( QString() )
    , mIssuerId( QString() )
    , mIssuerSelf( false )
{
}

bool QgsAuthenticationConfigPki::isValid() const
{
  return (
           QgsAuthenticationConfigBase::isValid()
           && !mCertId.isEmpty()
           && !mKeyId.isEmpty()
         );
}

const QString QgsAuthenticationConfigPki::configString() const
{
  QStringList configlist = QStringList();
  configlist << mCertId << mKeyId << mKeyPass << mIssuerId << QString::number( mIssuerSelf );
  return configlist.join( mConfSep );
}

void QgsAuthenticationConfigPki::loadConfigString( const QString& config )
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
