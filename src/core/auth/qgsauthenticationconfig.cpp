/***************************************************************************
    qgsauthenticationconfig.cpp
    ---------------------
    begin                : October 5, 2014
    copyright            : (C) 2014 by Boundless Spatial, Inc. USA
    author               : Larry Shaffer
    email                : lshaffer at boundlessgeo dot com
 ***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include "qgsauthenticationconfig.h"

#include "qgsauthenticationmanager.h"
#include "qgsauthenticationprovider.h"

#include <QFile>
#include <QObject>


const QHash<QgsAuthType::ProviderType, QString> QgsAuthType::typeNameHash()
{
  QHash<QgsAuthType::ProviderType, QString> typeNames;
  typeNames.insert( QgsAuthType::None, QObject::tr( "None" ) );
  typeNames.insert( QgsAuthType::Basic, QObject::tr( "Basic" ) );
#ifndef QT_NO_OPENSSL
  typeNames.insert( QgsAuthType::PkiPaths, QObject::tr( "PKI-Paths" ) );
  typeNames.insert( QgsAuthType::PkiPkcs12, QObject::tr( "PKI-PKCS#12" ) );
#endif
  typeNames.insert( QgsAuthType::Unknown, QObject::tr( "Unknown" ) );
  return typeNames;
}

QgsAuthType::ProviderType QgsAuthType::providerTypeFromInt( int itype )
{
  QgsAuthType::ProviderType ptype = Unknown;
  switch ( itype )
  {
    case 0:
      ptype = None;
      break;
    case 1:
      ptype = Basic;
      break;
#ifndef QT_NO_OPENSSL
    case 2:
      ptype = PkiPaths;
      break;
    case 3:
      ptype = PkiPkcs12;
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

const QString QgsAuthType::typeToString( QgsAuthType::ProviderType providertype )
{
  return QgsAuthType::typeNameHash().value( providertype, QObject::tr( "Unknown" ) );
}

QgsAuthType::ProviderType QgsAuthType::stringToType( const QString& name )
{
  return QgsAuthType::typeNameHash().key( name, QgsAuthType::Unknown );
}

const QString QgsAuthType::typeDescription( QgsAuthType::ProviderType providertype )
{
  QString s = QObject::tr( "No authentication set" );
  switch ( providertype )
  {
    case None:
      break;
    case Basic:
      s = QObject::tr( "Basic authentication" );
      break;
#ifndef QT_NO_OPENSSL
    case PkiPaths:
      s = QObject::tr( "PKI paths authentication" );
      break;
    case PkiPkcs12:
      s = QObject::tr( "PKI PKCS#12 authentication" );
      break;
#endif
    case Unknown:
      s = QObject::tr( "Unsupported authentication" );
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

const QString QgsAuthConfigBase::typeToString() const
{
  return QgsAuthType::typeToString( mType );
}

bool QgsAuthConfigBase::isValid( bool validateid ) const
{
  bool idvalid = validateid ? !mId.isEmpty() : true;

  return (
           idvalid
           && !mName.isEmpty()
           && mType != QgsAuthType::Unknown
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
           && mVersion != 0
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
// QgsAuthConfigPkiPaths
//////////////////////////////////////////////

QgsAuthConfigPkiPaths::QgsAuthConfigPkiPaths()
    : QgsAuthConfigBase( QgsAuthType::PkiPaths, 1 )
    , mCertId( QString() )
    , mKeyId( QString() )
    , mKeyPass( QString() )
    , mCaCertsId( QString() )
    , mIgnoreSelf( false )
{
}

const QString QgsAuthConfigPkiPaths::certAsPem() const
{
  if ( !isValid() )
    return QString();

  return QString( QgsAuthProviderPkiPaths::certAsPem( certId() ) );
}

const QStringList QgsAuthConfigPkiPaths::keyAsPem( bool reencrypt ) const
{
  if ( !isValid() )
    return QStringList() << QString() << QString();

  QString algtype;
  QByteArray keydata( QgsAuthProviderPkiPaths::keyAsPem( keyId(), keyPassphrase(), &algtype, reencrypt ) );
  return QStringList() << QString( keydata ) << algtype;
}

const QString QgsAuthConfigPkiPaths::caCertsAsPem() const
{
  if ( !isValid() )
    return QString();

  return QString( QgsAuthProviderPkiPaths::caCertsAsPem( caCertsId() ) );
}

bool QgsAuthConfigPkiPaths::isValid( bool validateid ) const
{
  return (
           QgsAuthConfigBase::isValid( validateid )
           && mVersion != 0
           && !mCertId.isEmpty()
           && !mKeyId.isEmpty()
         );
}

const QString QgsAuthConfigPkiPaths::configString() const
{
  QStringList configlist = QStringList();
  configlist << mCertId << mKeyId << mKeyPass << mCaCertsId << QString::number( mIgnoreSelf );
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
  mCaCertsId = configlist.at( 3 );
  mIgnoreSelf = ( bool ) configlist.at( 4 ).toInt();
}

//////////////////////////////////////////////
// QgsAuthConfigPkiPkcs12
//////////////////////////////////////////////

QgsAuthConfigPkiPkcs12::QgsAuthConfigPkiPkcs12()
    : QgsAuthConfigBase( QgsAuthType::PkiPkcs12, 1 )
    , mBundlePath( QString() )
    , mBundlePass( QString() )
    , mCaCertsPath( QString() )
    , mIgnoreSelf( false )
{
}

const QString QgsAuthConfigPkiPkcs12::certAsPem() const
{
  if ( !isValid() )
    return QString();

  return QgsAuthProviderPkiPkcs12::certAsPem( bundlePath(), bundlePassphrase() );
}

const QStringList QgsAuthConfigPkiPkcs12::keyAsPem( bool reencrypt ) const
{
  if ( !isValid() )
    return QStringList();

  QStringList keylist;
  keylist << QgsAuthProviderPkiPkcs12::keyAsPem( bundlePath(), bundlePassphrase(), reencrypt );
  keylist << QString( "rsa" );
  return keylist;
}

const QString QgsAuthConfigPkiPkcs12::caCertsAsPem() const
{
  if ( !isValid() )
    return QString();

  return QgsAuthProviderPkiPkcs12::caCertsAsPem( bundlePath(), bundlePassphrase(), caCertsPath() );
}

bool QgsAuthConfigPkiPkcs12::isValid( bool validateid ) const
{
  // TODO: add more robust validation via QCA (primary cert, key and CA chain)?
  return (
           QgsAuthConfigBase::isValid( validateid )
           && version() != 0
           && !bundlePath().isEmpty()
           && QFile::exists( bundlePath() )
         );
}

const QString QgsAuthConfigPkiPkcs12::configString() const
{
  QStringList configlist = QStringList();
  configlist << bundlePath() << bundlePassphrase() << caCertsPath() << QString::number( ignoreSelfSigned() );
  return configlist.join( mConfSep );
}

void QgsAuthConfigPkiPkcs12::loadConfigString( const QString &config )
{
  if ( config.isEmpty() )
    return;

  QStringList configlist = config.split( mConfSep );
  setBundlePath( configlist.at( 0 ) );
  setBundlePassphrase( configlist.at( 1 ) );
  setCaCertsPath( configlist.at( 2 ) );
  setIgnoreSelfSigned(( bool ) configlist.at( 3 ).toInt() );
}


//////////////////////////////////////////////
// QgsAuthConfigSslServer
//////////////////////////////////////////////

#ifndef QT_NO_OPENSSL

const QString QgsAuthConfigSslServer::mConfSep = "|||";

QgsAuthConfigSslServer::QgsAuthConfigSslServer()
  : mSslHost( QString() )
  , mSslCert( QSslCertificate() )
  , mSslIgnoredErrors( QList<QSslError>() )
  , mSslPeerVerify( qMakePair( QSslSocket::VerifyPeer, 0 ) )
  , mVersion( 1 )
{
#if QT_VERSION >= 0x040800
  mQtVersion = 480;
  // Qt 4.8 defaults to SecureProtocols, i.e. TlsV1SslV3
  // http://qt-project.org/doc/qt-4.8/qssl.html#SslProtocol-enum
  mSslProtocol = QSsl::SecureProtocols;
#else
  mQtVersion = 470;
  // older Qt 4.7 defaults to now-vulnerable SSLv3
  // http://qt-project.org/doc/qt-4.7/qssl.html
  // Default this to TlsV1 instead
  mSslProtocol = QSsl::TlsV1;
#endif
}

const QString QgsAuthConfigSslServer::configString() const
{
  QStringList configlist;
  configlist << QString::number( mVersion ) << QString::number( mQtVersion );

  configlist << QString::number(( int )mSslProtocol );

  QStringList errs;
  Q_FOREACH( const QSslError& err, mSslIgnoredErrors )
  {
    errs << QString::number(( int )err.error() );
  }
  configlist << errs.join( "~~" );

  configlist << QString( "%1~~%2" ).arg(( int )mSslPeerVerify.first ).arg( mSslPeerVerify.second );

  return configlist.join( mConfSep );
}

void QgsAuthConfigSslServer::loadConfigString( const QString &config )
{
  if ( config.isEmpty() )
  {
    return;
  }
  QStringList configlist( config.split( mConfSep ) );

  mVersion = configlist.at( 0 ).toInt();
  mQtVersion = configlist.at( 1 ).toInt();

  // TODO: Conversion between 4.7 -> 4.8 protocol enum differences (and reverse?).
  //       This is necessary for users upgrading from 4.7 to 4.8
  mSslProtocol = ( QSsl::SslProtocol )configlist.at( 2 ).toInt();

  mSslIgnoredErrors.clear();
  QStringList errs( configlist.at( 3 ).split( "~~" ) );
  Q_FOREACH( const QString& err, errs )
  {
    mSslIgnoredErrors.append( QSslError(( QSslError::SslError )err.toInt() ) );
  }

  QStringList peerverify( configlist.at( 4 ).split( "~~" ) );
  mSslPeerVerify = qMakePair(( QSslSocket::PeerVerifyMode )peerverify.at( 0 ).toInt(),
                             peerverify.at( 1 ).toInt() );
}

bool QgsAuthConfigSslServer::isNull() const
{
  return mSslCert.isNull() && mSslHost.isEmpty();
}

#endif
