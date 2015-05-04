/***************************************************************************
    qgsauthenticationcertutils.cpp
    ---------------------
    begin                : May 1, 2015
    copyright            : (C) 2015 by Boundless Spatial, Inc. USA
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

#include "qgsauthenticationcertutils.h"

#include <QColor>
#include <QFile>
#include <QObject>
#include <QSslCertificate>

#include "qgsauthenticationmanager.h"
#include "qgslogger.h"


const QColor QgsAuthCertUtils::greenColor()
{
  return QColor( 0, 170, 0 );
}

const QColor QgsAuthCertUtils::redColor()
{
  return QColor( 200, 0, 0 );
}

const QString QgsAuthCertUtils::greenTextStyleSheet( const QString &selector )
{
  return QString( "%1{color: %2;}" ).arg( selector ).arg( QgsAuthCertUtils::greenColor().name() );
}

const QString QgsAuthCertUtils::redTextStyleSheet( const QString &selector )
{
  return QString( "%1{color: %2;}" ).arg( selector ).arg( QgsAuthCertUtils::redColor().name() );
}

const QMap<QString, QSslCertificate> QgsAuthCertUtils::mapDigestToCerts( QList<QSslCertificate> certs )
{
  QMap<QString, QSslCertificate> digestmap;
  Q_FOREACH( QSslCertificate cert, certs )
  {
    digestmap.insert( shaHexForCert( cert ), cert );
  }
  return digestmap;
}

const QMap<QString, QList<QSslCertificate> > QgsAuthCertUtils::certsGroupedByOrg(QList<QSslCertificate> certs)
{
  QMap< QString, QList<QSslCertificate> > orgcerts;
  Q_FOREACH( QSslCertificate cert, certs )
  {
    QString org( cert.subjectInfo( QSslCertificate::Organization ) );
    if ( org.isEmpty() )
      org = "(Organization not defined)";
    QList<QSslCertificate> valist = orgcerts.contains( org ) ? orgcerts.value( org ) : QList<QSslCertificate>();
    orgcerts.insert( org, valist << cert );
  }
  return orgcerts;
}

static QByteArray fileData_( const QString& path, bool astext = false )
{
  QByteArray data;
  QFile file( path );
  if ( file.exists() )
  {
    QFile::OpenMode openflags( QIODevice::ReadOnly );
    if ( astext )
      openflags |= QIODevice::Text;
    bool ret = file.open( openflags );
    if ( ret )
    {
      data = file.readAll();
    }
    file.close();
  }
  return data;
}

const QList<QSslCertificate> QgsAuthCertUtils::certsFromFile( const QString &certspath )
{
  QList<QSslCertificate> certs;
  bool pem = certspath.endsWith( ".pem", Qt::CaseInsensitive );
  certs = QSslCertificate::fromData( fileData_( certspath, pem ), pem ? QSsl::Pem : QSsl::Der );
  if ( certs.isEmpty() )
  {
    QgsDebugMsg( QString( "Parsed cert(s) EMPTY for path: %1" ).arg( certspath ) );
  }
  return certs;
}

const QList<QSslCertificate> QgsAuthCertUtils::certsFromString( const QString &pemtext )
{
  QList<QSslCertificate> certs;
  certs = QSslCertificate::fromData( pemtext.toAscii(), QSsl::Pem );
  if ( certs.isEmpty() )
  {
    QgsDebugMsg( "Parsed cert(s) EMPTY" );
  }
  return certs;
}

const QString QgsAuthCertUtils::getCaSourceName( QgsAuthCertUtils::CaCertSource source, bool single )
{
  QString name;
  switch( source )
  {
    case SystemRoot:
      name = single ? QObject::tr( "System Root CA" ) : QObject::tr( "System Root Authorities" );
      break;
    case FromFile:
      name = single ? QObject::tr( "File CA" ) : QObject::tr( "Authorities from File" );
      break;
    case InDatabase:
      name = single ? QObject::tr( "Database CA" ) : QObject::tr( "Authorities in Database" );
      break;
    default:
      break;
  }

  return name;
}

const QString QgsAuthCertUtils::resolvedCertName( QSslCertificate cert )
{
  QString name( cert.subjectInfo( QSslCertificate::CommonName ) );

  if ( name.isEmpty() )
    name = cert.subjectInfo( QSslCertificate::OrganizationalUnitName );

  if ( name.isEmpty() )
    name = cert.subjectInfo( QSslCertificate::Organization );

  if ( name.isEmpty() )
    name = cert.subjectInfo( QSslCertificate::LocalityName );

  if ( name.isEmpty() )
    name = cert.subjectInfo( QSslCertificate::StateOrProvinceName );

  if ( name.isEmpty() )
    name = cert.subjectInfo( QSslCertificate::CountryName );

  return name;
}

const QString QgsAuthCertUtils::getCertTrustName( QgsAuthCertUtils::CertTrustPolicy trust )
{
  QString name;
  switch( trust )
  {
    case DefaultTrust:
      name = QObject::tr( "Default policy" );
      break;
    case Trusted:
      name = QObject::tr( "Trusted" );
      break;
    case Untrusted:
      name = QObject::tr( "Untrusted" );
      break;
    default:
      break;
  }

  return name;
}

const QString QgsAuthCertUtils::shaHexForCert( const QSslCertificate& cert )
{
  return QString( cert.digest( QCryptographicHash::Sha1 ).toHex() );
}

const QString QgsAuthCertUtils::qcaValidityMessage( QCA::Validity validity )
{
  QString msg;
  switch( validity )
  {
    case QCA::ValidityGood:
      msg = QObject::tr( "Certificate is valid." );
      break;
    case QCA::ErrorRejected:
      msg = QObject::tr( "Root CA rejected the certificate purpose." );
      break;
    case QCA::ErrorUntrusted:
      msg = QObject::tr( "Certificate is not trusted." );
      break;
    case QCA::ErrorSignatureFailed:
      msg = QObject::tr( "Signature does not match." );
      break;
    case QCA::ErrorInvalidCA:
      msg = QObject::tr( "Certificate Authority is invalid or not found." );
      break;
    case QCA::ErrorInvalidPurpose:
      msg = QObject::tr( "Purpose does not match the intended usage." );
      break;
    case QCA::ErrorSelfSigned:
      msg = QObject::tr( "Certificate is self-signed, and is not found in the list of trusted certificates." );
      break;
    case QCA::ErrorRevoked:
      msg = QObject::tr( "Certificate has been revoked." );
      break;
    case QCA::ErrorPathLengthExceeded:
      msg = QObject::tr( "Path length from the root CA to this certificate is too long." );
      break;
    case QCA::ErrorExpired:
      msg = QObject::tr( "Certificate has expired or is not yet valid." );
      break;
    case QCA::ErrorExpiredCA:
      msg = QObject::tr( "Certificate Authority has expired." );
      break;
    case QCA::ErrorValidityUnknown:
      msg = QObject::tr( "Validity is unknown." );
      break;
    default:
      break;
  }

  return msg;
}

bool QgsAuthCertUtils::certificateIsAuthorityOrIssuer( const QSslCertificate &cert )
{
  if ( QgsAuthManager::instance()->isDisabled() )
    return false;

  QCA::ConvertResult res;
  QCA::Certificate qcacert( QCA::Certificate::fromPEM( cert.toPem(), &res, QString( "qca-ossl" ) ) );
  if ( res == QCA::ConvertGood && !qcacert.isNull() && qcacert.isCA() )
  {
    QgsDebugMsg( "Certificate has 'CA:TRUE' basic constraint" );
    return true;
  }
  // if not basic constraint CA:TRUE defined, see if key usage allows cert signing, e.g. issuer cert
  QList<QCA::ConstraintType> certconsts = qcacert.constraints();
  Q_FOREACH( QCA::ConstraintType certconst, certconsts )
  {
    if ( certconst.known() == QCA::KeyCertificateSign )
    {
      QgsDebugMsg( "Certificate has 'Certificate Sign' key usage" );
      return true;
    }
  }

  return false;
}
