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

const QString QgsAuthCertUtils::resolvedCertName( const QSslCertificate &cert, bool issuer )
{
  QString name( issuer ? cert.issuerInfo( QSslCertificate::CommonName )
                       : cert.subjectInfo( QSslCertificate::CommonName ) );

  if ( name.isEmpty() )
    name = issuer ? cert.issuerInfo( QSslCertificate::OrganizationalUnitName )
                  : cert.subjectInfo( QSslCertificate::OrganizationalUnitName );

  if ( name.isEmpty() )
    name = issuer ? cert.issuerInfo( QSslCertificate::Organization )
                  : cert.subjectInfo( QSslCertificate::Organization );

  if ( name.isEmpty() )
    name = issuer ? cert.issuerInfo( QSslCertificate::LocalityName )
                  : cert.subjectInfo( QSslCertificate::LocalityName );

  if ( name.isEmpty() )
    name = issuer ? cert.issuerInfo( QSslCertificate::StateOrProvinceName )
                  : cert.subjectInfo( QSslCertificate::StateOrProvinceName );

  if ( name.isEmpty() )
    name = issuer ? cert.issuerInfo( QSslCertificate::CountryName )
                  : cert.subjectInfo( QSslCertificate::CountryName );

  return name;
}

// private
void QgsAuthCertUtils::appendDirSegment_( QStringList &dirname,
                                          const QString& segment, QString value )
{
  if ( !value.isEmpty() )
  {
    dirname.append( segment + "=" + value.replace( ",", "\\," ) );
  }
}

const QString QgsAuthCertUtils::getCertDistinguishedName( const QSslCertificate &qcert ,
                                                          const QCA::Certificate &acert ,
                                                          bool issuer )
{
  if ( QgsAuthManager::instance()->isDisabled() )
    return QString();

  if ( acert.isNull() )
  {
    QCA::ConvertResult res;
    QCA::Certificate acert( QCA::Certificate::fromPEM( qcert.toPem(), &res, QString( "qca-ossl" ) ) );
    if ( res != QCA::ConvertGood || acert.isNull() )
    {
      QgsDebugMsg( "Certificate could not be converted to QCA cert" );
      return QString();
    }
  }
  //  E=testcert@boundlessgeo.com,
  //  CN=Boundless Test Root CA,
  //  OU=Certificate Authority,
  //  O=Boundless Test CA,
  //  L=District of Columbia,
  //  ST=Washington\, DC,
  //  C=US
  QStringList dirname;
  QgsAuthCertUtils::appendDirSegment_(
        dirname, "E", issuer ? acert.issuerInfo().value( QCA::Email )
                             : acert.subjectInfo().value( QCA::Email ) );
  QgsAuthCertUtils::appendDirSegment_(
        dirname, "CN", issuer ? qcert.issuerInfo( QSslCertificate::CommonName )
                              : qcert.subjectInfo( QSslCertificate::CommonName ) );
  QgsAuthCertUtils::appendDirSegment_(
        dirname, "OU", issuer ? qcert.subjectInfo( QSslCertificate::OrganizationalUnitName )
                              : qcert.subjectInfo( QSslCertificate::OrganizationalUnitName ) );
  QgsAuthCertUtils::appendDirSegment_(
        dirname, "O", issuer ? qcert.subjectInfo( QSslCertificate::Organization )
                             : qcert.subjectInfo( QSslCertificate::Organization ) );
  QgsAuthCertUtils::appendDirSegment_(
        dirname, "L", issuer ? qcert.subjectInfo( QSslCertificate::LocalityName )
                             : qcert.subjectInfo( QSslCertificate::LocalityName ) );
  QgsAuthCertUtils::appendDirSegment_(
        dirname, "ST", issuer ? qcert.subjectInfo( QSslCertificate::StateOrProvinceName )
                              : qcert.subjectInfo( QSslCertificate::StateOrProvinceName ) );
  QgsAuthCertUtils::appendDirSegment_(
        dirname, "C", issuer ? qcert.subjectInfo( QSslCertificate::CountryName )
                             : qcert.subjectInfo( QSslCertificate::CountryName ) );

  return dirname.join("," );
}

const QString QgsAuthCertUtils::getCertTrustName( QgsAuthCertUtils::CertTrustPolicy trust )
{
  QString name;
  switch( trust )
  {
    case DefaultTrust:
      name = QObject::tr( "Default" );
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

const QString QgsAuthCertUtils::getColonDelimited( const QString &txt )
{
  // 64321c05b0ebab8e2b67ec0d7d9e2b6d4bc3c303
  //   -> 64:32:1c:05:b0:eb:ab:8e:2b:67:ec:0d:7d:9e:2b:6d:4b:c3:c3:03
  QStringList sl;
  for ( int i = 0; i < txt.size(); i += 2 )
  {
    sl << txt.mid( i, ( i + 2 > txt.size() ) ? -1 : 2 );
  }
  return sl.join( ":" );
}

const QString QgsAuthCertUtils::shaHexForCert( const QSslCertificate& cert, bool formatted )
{
  QString sha( cert.digest( QCryptographicHash::Sha1 ).toHex() );
  if ( formatted )
  {
    return QgsAuthCertUtils::getColonDelimited( sha );
  }
  return sha;
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

const QString QgsAuthCertUtils::qcaSignatureAlgorithm( QCA::SignatureAlgorithm algorithm )
{
  QString msg;
  switch( algorithm )
  {
    case QCA::EMSA1_SHA1:
      msg = QObject::tr( "SHA1, with EMSA1" );
      break;
    case QCA::EMSA3_SHA1:
      msg = QObject::tr( "SHA1, with EMSA3" );
      break;
    case QCA::EMSA3_MD5:
      msg = QObject::tr( "MD5, with EMSA3" );
      break;
    case QCA::EMSA3_MD2:
      msg = QObject::tr( "MD2, with EMSA3" );
      break;
    case QCA::EMSA3_RIPEMD160:
      msg = QObject::tr( "RIPEMD160, with EMSA3" );
      break;
    case QCA::EMSA3_Raw:
      msg = QObject::tr( "EMSA3, without digest" );
      break;
    case QCA::EMSA3_SHA224:
      msg = QObject::tr( "SHA224, with EMSA3" );
      break;
    case QCA::EMSA3_SHA256:
      msg = QObject::tr( "SHA256, with EMSA3" );
      break;
    case QCA::EMSA3_SHA384:
      msg = QObject::tr( "SHA384, with EMSA3" );
      break;
    case QCA::EMSA3_SHA512:
      msg = QObject::tr( "SHA512, with EMSA3" );
      break;
    default:
      msg = QObject::tr( "Unknown (possibly Elliptic Curve)" );
      break;
  }
  return msg;
}

const QString QgsAuthCertUtils::qcaKnownConstraint(QCA::ConstraintTypeKnown constraint)
{
  QString msg;
  switch( constraint )
  {
    case QCA::DigitalSignature:
      msg = QObject::tr( "Digital Signature" );
      break;
    case QCA::NonRepudiation:
      msg = QObject::tr( "Non-repudiation" );
      break;
    case QCA::KeyEncipherment:
      msg = QObject::tr( "Key Encipherment" );
      break;
    case QCA::DataEncipherment:
      msg = QObject::tr( "Data Encipherment" );
      break;
    case QCA::KeyAgreement:
      msg = QObject::tr( "Key Agreement" );
      break;
    case QCA::KeyCertificateSign:
      msg = QObject::tr( "Key Certificate Sign" );
      break;
    case QCA::CRLSign:
      msg = QObject::tr( "CRL Sign" );
      break;
    case QCA::EncipherOnly:
      msg = QObject::tr( "Encipher Only" );
      break;
    case QCA::DecipherOnly:
      msg = QObject::tr( "Decipher Only" );
      break;
    case QCA::ServerAuth:
      msg = QObject::tr( "Server Authentication" );
      break;
    case QCA::ClientAuth:
      msg = QObject::tr( "Client Authentication" );
      break;
    case QCA::CodeSigning:
      msg = QObject::tr( "Code Signing" );
      break;
    case QCA::EmailProtection:
      msg = QObject::tr( "Email Protection" );
      break;
    case QCA::IPSecEndSystem:
      msg = QObject::tr( "IPSec Endpoint" );
      break;
    case QCA::IPSecTunnel:
      msg = QObject::tr( "IPSec Tunnel" );
      break;
    case QCA::IPSecUser:
      msg = QObject::tr( "IPSec User" );
      break;
    case QCA::TimeStamping:
      msg = QObject::tr( "Time Stamping" );
      break;
    case QCA::OCSPSigning:
      msg = QObject::tr( "OCSP Signing" );
      break;
    default:
      break;
  }
  return msg;
}

bool QgsAuthCertUtils::certificateIsAuthority( const QSslCertificate &cert )
{
  if ( QgsAuthManager::instance()->isDisabled() )
    return false;

  QCA::ConvertResult res;
  QCA::Certificate qcacert( QCA::Certificate::fromPEM( cert.toPem(), &res, QString( "qca-ossl" ) ) );
  if ( res != QCA::ConvertGood || qcacert.isNull() )
  {
    QgsDebugMsg( "Certificate could not be converted to QCA cert" );
    return false;
  }
  if ( qcacert.isCA() )
  {
    QgsDebugMsg( "Certificate has 'CA:TRUE' basic constraint" );
    return true;
  }
  return false;
}

bool QgsAuthCertUtils::certificateIsIssuer( const QSslCertificate &cert )
{
  if ( QgsAuthManager::instance()->isDisabled() )
    return false;

  QCA::ConvertResult res;
  QCA::Certificate qcacert( QCA::Certificate::fromPEM( cert.toPem(), &res, QString( "qca-ossl" ) ) );
  if ( res != QCA::ConvertGood || qcacert.isNull() )
  {
    QgsDebugMsg( "Certificate could not be converted to QCA cert" );
    return false;
  }

  // see if key usage allows cert signing, e.g. issuer cert
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

bool QgsAuthCertUtils::certificateIsAuthorityOrIssuer( const QSslCertificate &cert )
{
  return ( QgsAuthCertUtils::certificateIsAuthority( cert )
           || QgsAuthCertUtils::certificateIsIssuer( cert ) );
}
