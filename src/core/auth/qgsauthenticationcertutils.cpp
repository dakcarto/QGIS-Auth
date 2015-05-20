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

const QColor QgsAuthCertUtils::orangeColor()
{
  return QColor( 255, 128, 0 );
}

const QColor QgsAuthCertUtils::redColor()
{
  return QColor( 200, 0, 0 );
}

const QString QgsAuthCertUtils::greenTextStyleSheet( const QString &selector )
{
  return QString( "%1{color: %2;}" ).arg( selector ).arg( QgsAuthCertUtils::greenColor().name() );
}

const QString QgsAuthCertUtils::orangeTextStyleSheet(const QString &selector)
{
  return QString( "%1{color: %2;}" ).arg( selector ).arg( QgsAuthCertUtils::orangeColor().name() );
}

const QString QgsAuthCertUtils::redTextStyleSheet( const QString &selector )
{
  return QString( "%1{color: %2;}" ).arg( selector ).arg( QgsAuthCertUtils::redColor().name() );
}

const QString QgsAuthCertUtils::getSslProtocolName( QSsl::SslProtocol protocol )
{
  QString name;
  switch( protocol )
  {
#if QT_VERSION >= 0x040800
    case QSsl::SecureProtocols:
      name = QObject::tr( "SecureProtocols" );
      break;
    case QSsl::TlsV1SslV3:
      name = QObject::tr( "TlsV1SslV3" );
      break;
#endif
    case QSsl::TlsV1:
      name = QObject::tr( "TlsV1" );
      break;
    case QSsl::SslV3:
      name = QObject::tr( "SslV3" );
      break;
    case QSsl::SslV2:
      name = QObject::tr( "SslV2" );
      break;
    default:
      break;
  }

  return name;
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

const QMap<QString, QgsAuthConfigSslServer> QgsAuthCertUtils::mapDigestToSslConfigs(QList<QgsAuthConfigSslServer> configs)
{
  QMap<QString, QgsAuthConfigSslServer> digestmap;
  Q_FOREACH( QgsAuthConfigSslServer config, configs )
  {
    digestmap.insert( shaHexForCert( config.sslCertificate() ), config );
  }
  return digestmap;
}

const QMap<QString, QList<QgsAuthConfigSslServer> > QgsAuthCertUtils::sslConfigsGroupedByOrg( QList<QgsAuthConfigSslServer> configs )
{
  QMap< QString, QList<QgsAuthConfigSslServer> > orgconfigs;
  Q_FOREACH( QgsAuthConfigSslServer config, configs )
  {
    QString org( config.sslCertificate().subjectInfo( QSslCertificate::Organization ) );
    if ( org.isEmpty() )
      org = QObject::tr( "(Organization not defined)" );
    QList<QgsAuthConfigSslServer> valist = orgconfigs.contains( org ) ? orgconfigs.value( org ) : QList<QgsAuthConfigSslServer>();
    orgconfigs.insert( org, valist << config );
  }
  return orgconfigs;
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
    case Connection:
      name = single ? QObject::tr( "Connection CA" ) : QObject::tr( "Authorities from connection" );
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

const QCA::Certificate QgsAuthCertUtils::qtCertToQcaCert( const QSslCertificate &cert )
{
  if ( QgsAuthManager::instance()->isDisabled() )
    return QCA::Certificate();

  QCA::ConvertResult res;
  QCA::Certificate qcacert( QCA::Certificate::fromPEM( cert.toPem(), &res, QString( "qca-ossl" ) ) );
  if ( res != QCA::ConvertGood || qcacert.isNull() )
  {
    QgsDebugMsg( "Certificate could not be converted to QCA cert" );
    qcacert = QCA::Certificate();
  }
  return qcacert;
}

const QCA::CertificateCollection QgsAuthCertUtils::qtCertsToQcaCollection( const QList<QSslCertificate> &certs )
{
  QCA::CertificateCollection qcacoll;
  if ( QgsAuthManager::instance()->isDisabled() )
    return qcacoll;

  Q_FOREACH ( const QSslCertificate& cert, certs )
  {
    QCA::Certificate qcacert( qtCertToQcaCert( cert )  );
    if ( !qcacert.isNull() )
    {
      qcacoll.addCertificate( qcacert);
    }
  }
  return qcacoll;
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

const QString QgsAuthCertUtils::certificateUsageTypeString(QgsAuthCertUtils::CertUsageType usagetype)
{
  QString msg;
  switch( usagetype )
  {
    case QgsAuthCertUtils::AnyOrUnspecifiedUsage:
      msg = QObject::tr( "Any or unspecified" );
      break;
    case QgsAuthCertUtils::CertAuthorityUsage:
      msg = QObject::tr( "Certificate Authority" );
      break;
    case QgsAuthCertUtils::CertIssuerUsage:
      msg = QObject::tr( "Certificate Issuer" );
      break;
    case QgsAuthCertUtils::TlsServerUsage:
      msg = QObject::tr( "TLS/SSL Server" );
      break;
    case QgsAuthCertUtils::TlsServerEvUsage:
      msg = QObject::tr( "TLS/SSL Server EV" );
      break;
    case QgsAuthCertUtils::TlsClientUsage:
      msg = QObject::tr( "TLS/SSL Client" );
      break;
    case QgsAuthCertUtils::CodeSigningUsage:
      msg = QObject::tr( "Code Signing" );
      break;
    case QgsAuthCertUtils::EmailProtectionUsage:
      msg = QObject::tr( "Email Protection" );
      break;
    case QgsAuthCertUtils::TimeStampingUsage:
      msg = QObject::tr( "Time Stamping" );
      break;
    case QgsAuthCertUtils::CRLSigningUsage:
      msg = QObject::tr( "CRL Signing" );
      break;
    case QgsAuthCertUtils::UndeterminedUsage:
    default:
      msg = QObject::tr( "Undetermined usage" );
      break;
  }
  return msg;

}

QList<QgsAuthCertUtils::CertUsageType> QgsAuthCertUtils::certificateUsageTypes( const QSslCertificate &cert )
{
  QList<QgsAuthCertUtils::CertUsageType> usages;

  if ( QgsAuthManager::instance()->isDisabled() )
    return usages;

  QCA::ConvertResult res;
  QCA::Certificate qcacert( QCA::Certificate::fromPEM( cert.toPem(), &res, QString( "qca-ossl" ) ) );
  if ( res != QCA::ConvertGood || qcacert.isNull() )
  {
    QgsDebugMsg( "Certificate could not be converted to QCA cert" );
    return usages;
  }

  if ( qcacert.isCA() )
  {
    QgsDebugMsg( "Certificate has 'CA:TRUE' basic constraint" );
    usages << QgsAuthCertUtils::CertAuthorityUsage;
  }

  QList<QCA::ConstraintType> certconsts = qcacert.constraints();
  Q_FOREACH( QCA::ConstraintType certconst, certconsts )
  {
    if ( certconst.known() == QCA::KeyCertificateSign )
    {
      QgsDebugMsg( "Certificate has 'Certificate Sign' key usage" );
      usages << QgsAuthCertUtils::CertIssuerUsage;
    }
    else if ( certconst.known() == QCA::ServerAuth )
    {
      QgsDebugMsg( "Certificate has 'server authentication' extended key usage" );
      usages << QgsAuthCertUtils::TlsServerUsage;
    }
  }

  // ask QCA what it thinks about potential usages
  QCA::CertificateCollection trustedCAs(
        qtCertsToQcaCollection( QgsAuthManager::instance()->getTrustedCaCertsCache() ) );
  QCA::CertificateCollection untrustedCAs(
        qtCertsToQcaCollection( QgsAuthManager::instance()->getUntrustedCaCerts() ) );

  QCA::Validity v_any;
  v_any = qcacert.validate( trustedCAs, untrustedCAs, QCA::UsageAny, QCA::ValidateAll );
  if ( v_any == QCA::ValidityGood )
  {
    usages << QgsAuthCertUtils::AnyOrUnspecifiedUsage;
  }

  QCA::Validity v_tlsserver;
  v_tlsserver = qcacert.validate( trustedCAs, untrustedCAs, QCA::UsageTLSServer, QCA::ValidateAll );
  if ( v_tlsserver == QCA::ValidityGood )
  {
    if ( !usages.contains( QgsAuthCertUtils::TlsServerUsage ) )
    {
      usages << QgsAuthCertUtils::TlsServerUsage;
    }
  }

  // TODO: why doesn't this tag client certs?
  //       always seems to return QCA::ErrorInvalidPurpose (enum #5)
  QCA::Validity v_tlsclient;
  v_tlsclient = qcacert.validate( trustedCAs, untrustedCAs, QCA::UsageTLSClient, QCA::ValidateAll );
  //QgsDebugMsg( QString( "QCA::UsageTLSClient validity: %1" ).arg( ( int )v_tlsclient ) );
  if ( v_tlsclient == QCA::ValidityGood )
  {
    usages << QgsAuthCertUtils::TlsClientUsage;
  }

  // TODO: add TlsServerEvUsage, CodeSigningUsage, EmailProtectionUsage, TimeStampingUsage, CRLSigningUsage
  //       as they become necessary, since we do not want the overhead of checking just yet.

  return usages;
}

bool QgsAuthCertUtils::certificateIsAuthority( const QSslCertificate &cert )
{
  return certificateUsageTypes( cert ).contains( QgsAuthCertUtils::CertAuthorityUsage );
}

bool QgsAuthCertUtils::certificateIsIssuer( const QSslCertificate &cert )
{
  return certificateUsageTypes( cert ).contains( QgsAuthCertUtils::CertIssuerUsage );
}

bool QgsAuthCertUtils::certificateIsAuthorityOrIssuer( const QSslCertificate &cert )
{
  return ( QgsAuthCertUtils::certificateIsAuthority( cert )
           || QgsAuthCertUtils::certificateIsIssuer( cert ) );
}

bool QgsAuthCertUtils::certificateIsSslServer( const QSslCertificate &cert )
{
  return ( certificateUsageTypes( cert ).contains( QgsAuthCertUtils::TlsServerUsage )
           || certificateUsageTypes( cert ).contains( QgsAuthCertUtils::TlsServerEvUsage ) );
}

#if 0
bool QgsAuthCertUtils::certificateIsSslServer( const QSslCertificate &cert )
{
  // TODO: There is no difinitive method for strictly enforcing what determines an SSL server cert;
  //       only what it should not be able to do (cert sign, etc.). The logic here may need refined
  // see: http://security.stackexchange.com/a/26650

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
    QgsDebugMsg( "SSL server certificate has 'CA:TRUE' basic constraint (and should not)" );
    return false;
  }

  QList<QCA::ConstraintType> certconsts = qcacert.constraints();
  Q_FOREACH( QCA::ConstraintType certconst, certconsts )
  {
    if ( certconst.known() == QCA::KeyCertificateSign )
    {
      QgsDebugMsg( "SSL server certificate has 'Certificate Sign' key usage (and should not)" );
      return false;
    }
  }

  // check for common key usage and extended key usage constraints
  // see: https://www.ietf.org/rfc/rfc3280.txt  4.2.1.3(Key Usage) and  4.2.1.13(Extended Key Usage)
  bool serverauth = false;
  bool dsignature = false;
  bool keyencrypt = false;
  Q_FOREACH( QCA::ConstraintType certconst, certconsts )
  {
    if ( certconst.known() == QCA::DigitalSignature )
    {
      QgsDebugMsg( "SSL server certificate has 'digital signature' key usage" );
      dsignature = true;
    }
    else if ( certconst.known() == QCA::KeyEncipherment )
    {
      QgsDebugMsg( "SSL server certificate has 'key encipherment' key usage" );
      keyencrypt = true;
    }
    else if ( certconst.known() == QCA::KeyAgreement )
    {
      QgsDebugMsg( "SSL server certificate has 'key agreement' key usage" );
      keyencrypt = true;
    }
    else if ( certconst.known() == QCA::ServerAuth )
    {
      QgsDebugMsg( "SSL server certificate has 'server authentication' extended key usage" );
      serverauth = true;
    }
  }
  // From 4.2.1.13(Extended Key Usage):
  //   "If a certificate contains both a key usage extension and an extended
  //   key usage extension, then both extensions MUST be processed
  //   independently and the certificate MUST only be used for a purpose
  //   consistent with both extensions.  If there is no purpose consistent
  //   with both extensions, then the certificate MUST NOT be used for any
  //   purpose."

  if ( serverauth && dsignature && keyencrypt )
  {
    return true;
  }
  if ( dsignature && keyencrypt )
  {
    return true;
  }

  // lastly, check for DH key and key agreement
  bool keyagree = false;
  bool encipheronly = false;
  bool decipheronly = false;

  QCA::PublicKey pubkey( qcacert.subjectPublicKey() );
  // key size may be 0 for eliptical curve-based keys, in which case isDH() crashes QCA
  if ( pubkey.bitSize() > 0 && pubkey.isDH() )
  {
    keyagree = pubkey.canKeyAgree();
    if ( !keyagree )
    {
      return false;
    }
    Q_FOREACH( QCA::ConstraintType certconst, certconsts )
    {
      if ( certconst.known() == QCA::EncipherOnly )
      {
        QgsDebugMsg( "SSL server public key has 'encipher only' key usage" );
        encipheronly = true;
      }
      else if ( certconst.known() == QCA::DecipherOnly )
      {
        QgsDebugMsg( "SSL server public key has 'decipher only' key usage" );
        decipheronly = true;
      }
    }
    if ( !encipheronly && !decipheronly )
    {
      return true;
    }
  }
  return false;
}
#endif

bool QgsAuthCertUtils::certificateIsSslClient( const QSslCertificate &cert )
{
  return certificateUsageTypes( cert ).contains( QgsAuthCertUtils::TlsClientUsage );
}

const QList<QPair<QSslError::SslError, QString> > QgsAuthCertUtils::sslErrorEnumStrings()
{
  QList<QPair<QSslError::SslError, QString> > errenums;
  errenums << qMakePair( QSslError::UnableToGetIssuerCertificate,
                         QObject::tr( "Unable To Get Issuer Certificate" ) );
  errenums << qMakePair( QSslError::UnableToDecryptCertificateSignature,
                         QObject::tr( "Unable To Decrypt Certificate Signature" ) );
  errenums << qMakePair( QSslError::UnableToDecodeIssuerPublicKey,
                         QObject::tr( "Unable To Decode Issuer Public Key" ) );
  errenums << qMakePair( QSslError::CertificateSignatureFailed,
                         QObject::tr( "Certificate Signature Failed" ) );
  errenums << qMakePair( QSslError::CertificateNotYetValid,
                         QObject::tr( "Certificate Not Yet Valid" ) );
  errenums << qMakePair( QSslError::CertificateExpired,
                         QObject::tr( "Certificate Expired" ) );
  errenums << qMakePair( QSslError::InvalidNotBeforeField,
                         QObject::tr( "Invalid Not Before Field" ) );
  errenums << qMakePair( QSslError::InvalidNotAfterField,
                         QObject::tr( "Invalid Not After Field" ) );
  errenums << qMakePair( QSslError::SelfSignedCertificate,
                         QObject::tr( "Self-signed Certificate" ) );
  errenums << qMakePair( QSslError::SelfSignedCertificateInChain,
                         QObject::tr( "Self-signed Certificate In Chain" ) );
  errenums << qMakePair( QSslError::UnableToGetLocalIssuerCertificate,
                         QObject::tr( "Unable To Get Local Issuer Certificate" ) );
  errenums << qMakePair( QSslError::UnableToVerifyFirstCertificate,
                         QObject::tr( "Unable To Verify First Certificate" ) );
  errenums << qMakePair( QSslError::CertificateRevoked,
                         QObject::tr( "Certificate Revoked" ) );
  errenums << qMakePair( QSslError::InvalidCaCertificate,
                         QObject::tr( "Invalid Ca Certificate" ) );
  errenums << qMakePair( QSslError::PathLengthExceeded,
                         QObject::tr( "Path Length Exceeded" ) );
  errenums << qMakePair( QSslError::InvalidPurpose,
                         QObject::tr( "Invalid Purpose" ) );
  errenums << qMakePair( QSslError::CertificateUntrusted,
                         QObject::tr( "Certificate Untrusted" ) );
  errenums << qMakePair( QSslError::CertificateRejected,
                         QObject::tr( "Certificate Rejected" ) );
  errenums << qMakePair( QSslError::SubjectIssuerMismatch,
                         QObject::tr( "Subject Issuer Mismatch" ) );
  errenums << qMakePair( QSslError::AuthorityIssuerSerialNumberMismatch,
                         QObject::tr( "Authority Issuer Serial Number Mismatch" ) );
  errenums << qMakePair( QSslError::NoPeerCertificate,
                         QObject::tr( "No Peer Certificate" ) );
  errenums << qMakePair( QSslError::HostNameMismatch,
                         QObject::tr( "Host Name Mismatch" ) );
  errenums << qMakePair( QSslError::UnspecifiedError,
                         QObject::tr( "Unspecified Error" ) );
  errenums << qMakePair( QSslError::CertificateBlacklisted,
                         QObject::tr( "Certificate Blacklisted" ) );
  return errenums;
}
