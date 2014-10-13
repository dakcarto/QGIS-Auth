#ifndef QGSAUTHENTICATIONCRYPTO_H
#define QGSAUTHENTICATIONCRYPTO_H

#include <QString>

class QgsAuthCrypto
{

  public:
    static const QString encrypt( QString pass, QString cipheriv, QString text );

    static const QString decrypt( QString pass, QString cipheriv, QString text );

    static void passwordKeyHash( const QString &pass,
                                 QString *salt,
                                 QString *hash,
                                 QString *cipheriv = 0 );

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
