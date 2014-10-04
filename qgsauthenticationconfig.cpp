#include "qgsauthenticationconfig.h"

#include "qgsauthenticationmanager.h"
#include "qgsauthenticationprovider.h"

#include <QObject>


QgsAuthType::ProviderType QgsAuthType::providerTypeFromInt( int itype )
{
  ProviderType ptype = Unknown;
  switch ( itype )
  {
    case 0:
      ptype = None;
      break;
    case 1:
      ptype = None;
      break;
#ifndef QT_NO_OPENSSL
    case 2:
      ptype = PkiPaths;
      break;
#endif
    case 20:
      // Unknown
      break;
    default:
      break;
  }

  return ptype;

}

const QString QgsAuthType::typeAsString( QgsAuthType::ProviderType providertype )
{
  QString s = QObject::tr( "No authentication configuration set" );
  switch ( providertype )
  {
    case None:
      break;
    case Basic:
      s = QObject::tr( "Basic authentication configuration" );
      break;
#ifndef QT_NO_OPENSSL
    case PkiPaths:
      s = QObject::tr( "PKI paths authentication configuration" );
      break;
#endif
    case Unknown:
      s = QObject::tr( "Unsupported authentication configuration" );
      break;
    default:
      break;
  }
  return s;
}


//////////////////////////////////////////////
// QgsAuthConfigBase
//////////////////////////////////////////////

const QString QgsAuthConfigBase::mConfSep = "|||";

// get uniqueConfigId only on save
QgsAuthConfigBase::QgsAuthConfigBase( QgsAuthType::ProviderType type, int version )
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
  return QgsAuthType::typeAsString( mType );
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
           && mType != QgsAuthType::Unknown
           && mVersion != 0
         );
}

const QgsAuthConfigBase QgsAuthConfigBase::toBaseConfig()
{
  return QgsAuthConfigBase( *this );
}


//////////////////////////////////////////////
// QgsAuthConfigBasic
//////////////////////////////////////////////

QgsAuthConfigBasic::QgsAuthConfigBasic()
    : QgsAuthConfigBase( QgsAuthType::Basic, 1 )
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

//////////////////////////////////////////////
// QgsAuthConfigPki
//////////////////////////////////////////////

QgsAuthConfigPkiPaths::QgsAuthConfigPkiPaths()
    : QgsAuthConfigBase( QgsAuthType::PkiPaths, 1 )
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
