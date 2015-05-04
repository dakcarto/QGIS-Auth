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
      InDatabase = 2
    };

    enum CertTrustPolicy
    {
      DefaultTrust = 0,
      Trusted = 1,
      Untrusted = 2
    };

    /** Green color representing valid, trusted, etc. certificate */
    static const QColor greenColor();

    /** Red color representing invalid, untrusted, etc. certificate */
    static const QColor redColor();

    /** Green text stylesheet representing valid, trusted, etc. certificate */
    static const QString greenTextStyleSheet( const QString& selector = "*" );

    /** Red text stylesheet representing invalid, untrusted, etc. certificate */
    static const QString redTextStyleSheet( const QString& selector = "*" );


    /** Map certificate sha1 to certificate as simple cache */
    static const QMap< QString, QSslCertificate> mapDigestToCerts( QList<QSslCertificate> certs );

    /** Map certificates to their oraganization */
    static const QMap< QString, QList<QSslCertificate> > certsGroupedByOrg( QList<QSslCertificate> certs );

    /** Return list of concatenated certs from a PEM or DER formatted file */
    static const QList<QSslCertificate> certsFromFile( const QString &certspath );

    /** Return list of concatenated certs from a PEM Base64 text block */
    static const QList<QSslCertificate> certsFromString( const QString &pemtext );

    /** Get the general name for CA source */
    static const QString getCaSourceName( QgsAuthCertUtils::CaCertSource source , bool single = false );

    /** Get the general name via RFC 5280 resolution */
    static const QString resolvedCertName( QSslCertificate cert );

    /** Get the general name for certificate trust */
    static const QString getCertTrustName( QgsAuthCertUtils::CertTrustPolicy trust );

    /** Get the sha1 hash for certificate */
    static const QString shaHexForCert( const QSslCertificate &cert );

    /** Certificate validity check messages per enum */
    static const QString qcaValidityMessage( QCA::Validity validity );

    /** Certificate is an Authority */
    static bool certificateIsAuthorityOrIssuer( const QSslCertificate& cert );

};

#endif // QGSAUTHCERTUTILS_H
