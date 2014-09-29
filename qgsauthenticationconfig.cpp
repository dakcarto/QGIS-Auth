#include "qgsauthenticationconfig.h"

#include "qgsauthenticationmanager.h"

const QString QgsAuthenticationConfig::mConfSep = "|||";

QgsAuthenticationConfig::QgsAuthenticationConfig( ConfigType type, int version )
  : mId( QgsAuthenticationManager::instance()->uniqueConfigId() )
  , mName( QString() )
  , mUri( QString() )
  , mType( type )
  , mVersion( version )
{
}

bool QgsAuthenticationConfig::isValid() const
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

QgsAuthenticationConfigBasic::QgsAuthenticationConfigBasic()
  : QgsAuthenticationConfig( Basic, 1 )
  , mRealm( QString() )
  , mUsername( QString() )
  , mPassword( QString() )
{
}

bool QgsAuthenticationConfigBasic::isValid() const
{
  // password can be empty
  return (
    QgsAuthenticationConfig::isValid()
    && !mRealm.isEmpty()
    && !mUsername.isEmpty()
  );
}

const QString QgsAuthenticationConfigBasic::configString() const
{
  QStringList configlist = QStringList() << mRealm << mUsername << mPassword;
  return configlist.join( mConfSep );
}

QgsAuthenticationConfigPki::QgsAuthenticationConfigPki()
  : QgsAuthenticationConfig( PkiPaths, 1 )
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
    QgsAuthenticationConfig::isValid()
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
