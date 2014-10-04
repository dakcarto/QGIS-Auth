// This file is part of the Qrypto project
// Copyright (C) 2008-2010 Amine Roukh <amineroukh@gmail.com>
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 3
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; If not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.


#ifndef QGSAUTHENTICATIONCRYPTO_H
#define QGSAUTHENTICATIONCRYPTO_H

// for Mac, define CRYPTOPP_DISABLE_ASM for build, if
// libcryptopp.dylib was built that way as well, e.g. Homebrew's

#include "cryptopp/aes.h"
#include "cryptopp/blowfish.h"
#include "cryptopp/camellia.h"
#include "cryptopp/cast.h"
#include "cryptopp/des.h"
#include "cryptopp/gost.h"
#include "cryptopp/idea.h"
#include "cryptopp/mars.h"
#include "cryptopp/rc2.h"
#include "cryptopp/rc5.h"
#include "cryptopp/rc6.h"
#include "cryptopp/rijndael.h"
#include "cryptopp/safer.h"
#include "cryptopp/seed.h"
#include "cryptopp/serpent.h"
#include "cryptopp/shacal2.h"
#include "cryptopp/shark.h"
#include "cryptopp/skipjack.h"
#include "cryptopp/square.h"
#include "cryptopp/3way.h"
#include "cryptopp/twofish.h"
#include "cryptopp/tea.h"
#include "cryptopp/salsa.h"
#include "cryptopp/panama.h"
#include "cryptopp/seal.h"
#include "cryptopp/sosemanuk.h"

#include "cryptopp/osrng.h"
#include "cryptopp/pwdbased.h"

#include "cryptopp/modes.h" // xxx_Mode< >
#include "cryptopp/filters.h" // StringSource and StreamTransformation
#include "cryptopp/hex.h"
#include "cryptopp/sha.h"

#include <QString>

using namespace std;

class QgsAuthCrypto
{

  public:
    static const QString encrypt( QString pass, QString text, string cipher );

    static const QString decrypt( QString pass, QString text, string cipher );

    static void passwordHash( const QString &pass , QString *salt, QString *hash );

    static bool verifyPasswordHash( const QString& pass,
                                    const QString& salt,
                                    const QString& hash,
                                    QString *hashderived = 0 );

  private:
    static string encryption( QString Pass, QString Text, string cipher, bool encrypt );
};

#endif  // QGSAUTHENTICATIONCRYPTO_H
