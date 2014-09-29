#include "qgsauthenticationconfig.h"


QgsAuthenticationConfig::QgsAuthenticationConfig( ConfigType type, int version )
  : mId( QString() )
  , mName( QString() )
  , mUri( QString() )
  , mType( type )
  , mVersion( version )
{
}

bool QgsAuthenticationConfig::isValid()
{
  bool v = false;

  return v;
}

QgsAuthenticationConfigBasic::QgsAuthenticationConfigBasic()
  : QgsAuthenticationConfig( Basic, 1 )
  , mUsername( QString() )
  , mPassword( QString() )
{
}

bool QgsAuthenticationConfigBasic::isValid()
{
  bool v = QgsAuthenticationConfig::isValid();
  return v;
}

QgsAuthenticationConfigPkiPaths::QgsAuthenticationConfigPkiPaths()
  : QgsAuthenticationConfig( PkiPaths, 1 )
  , mCertPath( QString() )
  , mKeyPath( QString() )
  , mKeyPass( QString() )
  , mIssuerPath( QString() )
  , mIssuerSelf( false )
{
}

bool QgsAuthenticationConfigPkiPaths::isValid()
{
  return true;
}
