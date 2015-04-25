/***************************************************************************
    qgsauthenticationcrypto.h
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

#ifndef QGSAUTHENTICATIONCRYPTO_H
#define QGSAUTHENTICATIONCRYPTO_H

#include <QString>

/** \ingroup core
 * Funtions for hashing/checking master password and encrypt/decrypting data with password
 * \since 2.8
 */
class CORE_EXPORT QgsAuthCrypto
{

  public:
    /** Whether QCA has the qca-ossl plugin, which a base run-time requirement */
    static bool isDisabled();

    /** Encrypt data using master password */
    static const QString encrypt( QString pass, QString cipheriv, QString text );

    /** Decrypt data using master password */
    static const QString decrypt( QString pass, QString cipheriv, QString text );

    /** Generate SHA256 hash for master password, with iterations and salt */
    static void passwordKeyHash( const QString &pass,
                                 QString *salt,
                                 QString *hash,
                                 QString *cipheriv = 0 );

    /** Verify existing master password hash to a re-generated one */
    static bool verifyPasswordKeyHash( const QString& pass,
                                       const QString& salt,
                                       const QString& hash,
                                       QString *hashderived = 0 );

  private:
    static QString encryptdecrypt( QString passstr,
                                   QString cipheriv,
                                   QString textstr,
                                   bool encrypt );
};

#endif  // QGSAUTHENTICATIONCRYPTO_H
