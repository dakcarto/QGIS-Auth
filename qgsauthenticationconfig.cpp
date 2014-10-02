#include "qgsauthenticationconfig.h"

#include "qgsauthenticationmanager.h"

#include <QObject>

const QString QgsAuthenticationConfigBase::mConfSep = "|||";

QgsAuthenticationConfigBase::QgsAuthenticationConfigBase( ConfigType type, int version )
    : mId( QgsAuthenticationManager::instance()->uniqueConfigId() )
    , mName( QString() )
    , mUri( QString() )
    , mType( type )
    , mVersion( version )
{
}

const QString QgsAuthenticationConfigBase::typeAsString() const
{
  QString s = QObject::tr( "Null authentication" );
  switch ( mType ) {
    case None:
      break;
    case Basic:
      s = QObject::tr( "Basic authentication" );
    case PkiPaths:
      s = QObject::tr( "PKI paths authentication" );
    default:
      break;
  }
  return s;
}

bool QgsAuthenticationConfigBase::isValid() const
{
  return (
           !mId.isEmpty()
           && QgsAuthenticationManager::instance()->configIdUnique( mId )
           && !mName.isEmpty()
           && !mUri.isEmpty()
           && mType != Unknown
           && mVersion != 0
         );
}

QgsAuthenticationConfig::QgsAuthenticationConfig( ConfigType type, int version )
  : QgsAuthenticationConfigBase( type, version )
{

}

QgsAuthenticationConfigBasic::QgsAuthenticationConfigBasic()
    : QgsAuthenticationConfigBase( Basic, 1 )
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
  QStringList configlist = config.split( mConfSep );
  mRealm = configlist.at( 0 );
  mUsername = configlist.at( 1 );
  mPassword = configlist.at( 2 );
}

QgsAuthenticationConfigPki::QgsAuthenticationConfigPki()
    : QgsAuthenticationConfigBase( PkiPaths, 1 )
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
  QStringList configlist = config.split( mConfSep );
  mCertId = configlist.at( 0 );
  mKeyId = configlist.at( 1 );
  mKeyPass = configlist.at( 2 );
  mIssuerId = configlist.at( 3 );
  mIssuerSelf = ( bool ) configlist.at( 4 ).toInt();
}
