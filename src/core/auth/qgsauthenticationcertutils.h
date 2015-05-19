/***************************************************************************
    qgsauthenticationcertutils.h
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


#ifndef QGSAUTHCERTUTILS_H
#define QGSAUTHCERTUTILS_H

#include <QtCrypto>
#include <QSslCertificate>
#include <QSslError>

#include "qgsauthenticationconfig.h"

/** \ingroup core
 * \brief Utilities for working with certificates and keys
 * \since 2.9
 */
class CORE_EXPORT QgsAuthCertUtils
{
  public:
    enum CaCertSource
    {
      SystemRoot = 0,
      FromFile = 1,
      InDatabase = 2,
      Connection = 3
    };

    enum CertTrustPolicy
    {
      DefaultTrust = 0,
      Trusted = 1,
      Untrusted = 2,
      NoPolicy = 3
    };

    enum CertUsageType
    {
      UndeterminedUsage = 0,
      AnyOrUnspecifiedUsage,
      CertAuthorityUsage,
      CertIssuerUsage,
      TlsServerUsage,
      TlsServerEvUsage,
      TlsClientUsage,
      CodeSigningUsage,
      EmailProtectionUsage,
      TimeStampingUsage,
      CRLSigningUsage
    };

    enum ConstraintGroup
    {
      KeyUsage = 0,
      ExtendedKeyUsage = 1
    };

    /** Green color representing valid, trusted, etc. certificate */
    static const QColor greenColor();

    /** Orange color representing loaded component, but not stored in database */
    static const QColor orangeColor();

    /** Red color representing invalid, untrusted, etc. certificate */
    static const QColor redColor();

    /** Green text stylesheet representing valid, trusted, etc. certificate */
    static const QString greenTextStyleSheet( const QString& selector = "*" );

    /** Orange text stylesheet representing loaded component, but not stored in database */
    static const QString orangeTextStyleSheet( const QString& selector = "*" );

    /** Red text stylesheet representing invalid, untrusted, etc. certificate */
    static const QString redTextStyleSheet( const QString& selector = "*" );


    /** SSL Protocol name strings per enum */
    static const QString getSslProtocolName( QSsl::SslProtocol protocol );

    /** Map certificate sha1 to certificate as simple cache */
    static const QMap< QString, QSslCertificate> mapDigestToCerts( QList<QSslCertificate> certs );

    /** Map certificates to their oraganization */
    static const QMap< QString, QList<QSslCertificate> > certsGroupedByOrg( QList<QSslCertificate> certs );

    /** Map SSL custom configs' certificate sha1 to custom config as simple cache */
    static const QMap< QString, QgsAuthConfigSslServer> mapDigestToSslConfigs( QList<QgsAuthConfigSslServer> configs );

    /** Map SSL custom configs' certificates to their oraganization */
    static const QMap< QString, QList<QgsAuthConfigSslServer> > sslConfigsGroupedByOrg( QList<QgsAuthConfigSslServer> configs );

    /** Return list of concatenated certs from a PEM or DER formatted file */
    static const QList<QSslCertificate> certsFromFile( const QString &certspath );

    /** Return list of concatenated certs from a PEM Base64 text block */
    static const QList<QSslCertificate> certsFromString( const QString &pemtext );

    /** Get the general name for CA source */
    static const QString getCaSourceName( QgsAuthCertUtils::CaCertSource source , bool single = false );

    /** Get the general name via RFC 5280 resolution */
    static const QString resolvedCertName( const QSslCertificate& cert, bool issuer = false );

    /** Get combined directory name for certificate */
    static const QString getCertDistinguishedName( const QSslCertificate& qcert,
                                                   const QCA::Certificate& acert = QCA::Certificate(),
                                                   bool issuer = false );

    /** Get the general name for certificate trust */
    static const QString getCertTrustName( QgsAuthCertUtils::CertTrustPolicy trust );

    /** Get string with colon delimeters every 2 characters */
    static const QString getColonDelimited( const QString& txt );

    /** Get the sha1 hash for certificate */
    static const QString shaHexForCert( const QSslCertificate &cert , bool formatted = false );

    /** Convert a QSslCertificate to a QCA::Certificate */
    static const QCA::Certificate qtCertToQcaCert( const QSslCertificate& cert );

    /** Convert a QList of QSslCertificate to a QCA::CertificateCollection */
    static const QCA::CertificateCollection qtCertsToQcaCollection( const QList<QSslCertificate>& certs );

    /** Certificate validity check messages per enum */
    static const QString qcaValidityMessage( QCA::Validity validity );

    /** Certificate signature algorithm strings per enum */
    static const QString qcaSignatureAlgorithm( QCA::SignatureAlgorithm algorithm );

    /** Certificate well-known constraint strings per enum */
    static const QString qcaKnownConstraint( QCA::ConstraintTypeKnown constraint );

    /** Certificate usage type strings per enum */
    static const QString certificateUsageTypeString( QgsAuthCertUtils::CertUsageType usagetype );

    /** Try to determine the certificates usage types */
    static QList<QgsAuthCertUtils::CertUsageType> certificateUsageTypes( const QSslCertificate& cert );

    /** Get whether a certificate is an Authority */
    static bool certificateIsAuthority( const QSslCertificate& cert );

    /** Get whether a certificate can sign other certificates */
    static bool certificateIsIssuer( const QSslCertificate& cert );

    /** Get whether a certificate is an Authority or can at least sign other certificates */
    static bool certificateIsAuthorityOrIssuer( const QSslCertificate& cert );

    /** Get whether a certificate is probably used for a SSL server */
    static bool certificateIsSslServer( const QSslCertificate& cert );

    /** Get whether a certificate is probably used for a client identity */
    static bool certificateIsSslClient( const QSslCertificate& cert );

    /** Get short strings describing SSL errors */
    static const QList<QPair<QSslError::SslError, QString> > sslErrorEnumStrings();

  private:
    static void appendDirSegment_( QStringList &dirname, const QString &segment, QString value );
};

#endif // QGSAUTHCERTUTILS_H
