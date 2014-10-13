#ifndef QGSAUTHENTICATIONCRYPTO_H
#define QGSAUTHENTICATIONCRYPTO_H

#include <QtCrypto>
#include <QString>

class QgsAuthCrypto
{

  public:
    static const QString encrypt( QString pass, QString text, QString cipher );

    static const QString decrypt( QString pass, QString text, QString cipher );

    static void passwordHash( const QString &pass , QString *salt, QString *hash );

    static bool verifyPasswordHash( const QString& pass,
                                    const QString& salt,
                                    const QString& hash,
                                    QString *hashderived = 0 );

  private:
    static QString encryption( QString passstr, QString textstr, QString ciphername, bool encrypt );

    static QString encryptdecrypt( QString passstr, QString textstr, bool encrypt );
};

#endif  // QGSAUTHENTICATIONCRYPTO_H
