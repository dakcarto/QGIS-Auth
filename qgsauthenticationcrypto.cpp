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


#include "qgsauthenticationcrypto.h"

#include <string.h>

#include <QObject>

using namespace CryptoPP;
using namespace std;

const QString QgsAuthCrypto::encrypt( QString pass, QString text, string cipher )
{
  string res( encryption( pass, text, cipher, true ) );
  if ( res == "Unknown Error" )
    return QObject::tr( "Unknown error" );
  return QString::fromStdString( res );
}

const QString QgsAuthCrypto::decrypt( QString pass, QString text, string cipher )
{
  string res( encryption( pass, text, cipher, false ) );
  if ( res == "Unknown Error" )
    return QObject::tr( "Unknown error" );
  return QString::fromStdString( res );
}

void QgsAuthCrypto::passwordHash( const QString &pass, QString *salt, QString *hash )
{
  string password = pass.toStdString();
  unsigned int iterations = 10000;

  AutoSeededRandomPool rng;

  SecByteBlock pwsalt( SHA256::DIGESTSIZE );
  rng.GenerateBlock( pwsalt, pwsalt.size() );

  SecByteBlock derivedkey( SHA256::DIGESTSIZE );

  PKCS5_PBKDF2_HMAC<SHA256> pbkdf;

  pbkdf.DeriveKey(
    derivedkey, derivedkey.size(),
    0x00,
    ( byte * ) password.data(), password.size(),
    pwsalt, pwsalt.size(),
    iterations
  );
  string salthex;
  StringSource ps( pwsalt, pwsalt.size(), true,
                   new HexEncoder(
                     new StringSink( salthex )
                   )
                 );
  string derivedhex;
  StringSource dh( derivedkey, derivedkey.size(), true,
                   new HexEncoder(
                     new StringSink( derivedhex )
                   )
                 );

  // LEAVE THIS DEBUG OUTPUT COMMENTED OUT, except during testing of source edits
  //qDebug( "salt hex: %s", salthex.c_str() );
  *salt = encrypt( pass, QString::fromStdString( salthex ), "AES" );
  //qDebug( "salt hex encrypted (out): %s", salt->toStdString().c_str() );
  *hash = QString::fromStdString( derivedhex );
}

bool QgsAuthCrypto::verifyPasswordHash( const QString &pass,
                                        const QString &salt,
                                        const QString& hash,
                                        QString *hashderived )
{
  string password = pass.toStdString();
  // debug output to see if res was "Unknown Error"
  //qDebug( "salt hex encrypted (in): %s", salt.toStdString().c_str() );
  string salthex = decrypt( pass, salt, "AES" ).toStdString();
  // LEAVE THIS DEBUG OUTPUT COMMENTED OUT, except during testing of source edits
  //qDebug( "salt hex decrypted: %s", salthex.c_str() );
  string hashhex = hash.toStdString();
  unsigned int iterations = 10000;

  SecByteBlock pwsalt( SHA256::DIGESTSIZE );

  HexDecoder decoder;
  decoder.Put(( byte * ) salthex.data(), salthex.size() );
  decoder.MessageEnd();
  decoder.Get( pwsalt.BytePtr(), pwsalt.size() );

  SecByteBlock derivedkey( SHA256::DIGESTSIZE );

  PKCS5_PBKDF2_HMAC<SHA256> pbkdf;

  pbkdf.DeriveKey(
    derivedkey, derivedkey.size(),
    0x00,
    ( byte * ) password.data(), password.size(),
    pwsalt, pwsalt.size(),
    iterations
  );

  string derivedhex;
  StringSource dh( derivedkey, derivedkey.size(), true,
                   new HexEncoder(
                     new StringSink( derivedhex )
                   )
                 );

  if ( hashderived )
  {
    *hashderived = QString::fromStdString( derivedhex );
  }

  return derivedhex == hashhex;
}

string QgsAuthCrypto::encryption( QString Pass, QString Text, string cipher, bool encrypt )
{
  string text = Text.toStdString();
  string pass = Pass.toStdString();
  string CipherText;
  string RecoveredText;


  if ( cipher == "AES" )
  {
    byte key[ AES::DEFAULT_KEYLENGTH ], iv[ AES::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, AES::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, AES::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<AES>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<AES>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  if ( cipher == "Blowfish" )
  {
    byte key[ Blowfish::DEFAULT_KEYLENGTH ], iv[ Blowfish::BLOCKSIZE ];

    memset( iv, 0x00, Blowfish::BLOCKSIZE );

    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, Blowfish::DEFAULT_KEYLENGTH ) ) );
    //StringSource(pass, true, new HashFilter(*(new SHA256), new ArraySink(key, Blowfish::DEFAULT_KEYLENGTH)));


    if ( encrypt )
    {
      CBC_Mode<Blowfish>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<Blowfish>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        RecoveredText = e.what();
      }
      catch ( ... )
      {
        RecoveredText = "Unknown Error";
      }
    }
  }

  else if ( cipher == "Camellia" )
  {
    byte key[ Camellia::DEFAULT_KEYLENGTH ], iv[ Camellia::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, Camellia::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, Camellia::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<Camellia>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<Camellia>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "CAST128" )
  {
    byte key[ CAST128::DEFAULT_KEYLENGTH ], iv[ CAST128::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, CAST128::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, CAST128::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<CAST128>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<CAST128>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "CAST256" )
  {
    byte key[ CAST256::DEFAULT_KEYLENGTH ], iv[ CAST256::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, CAST256::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, CAST256::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<CAST256>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<CAST256>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "DES" )
  {
    byte key[ DES::DEFAULT_KEYLENGTH ], iv[ DES::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, DES::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, DES::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<DES>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<DES>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "DES_EDE2" )
  {
    byte key[ DES_EDE2::DEFAULT_KEYLENGTH ], iv[ DES_EDE2::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, DES_EDE2::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, DES_EDE2::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<DES_EDE2>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<DES_EDE2>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "DES_EDE3" )
  {
    byte key[ DES_EDE3::DEFAULT_KEYLENGTH ], iv[ DES_EDE3::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, DES_EDE3::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, DES_EDE3::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<DES_EDE3>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<DES_EDE3>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "DES_XEX3" )
  {
    byte key[ DES_XEX3::DEFAULT_KEYLENGTH ], iv[ DES_XEX3::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, DES_XEX3::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, DES_XEX3::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<DES_XEX3>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<DES_XEX3>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "GOST" )
  {
    byte key[ GOST::DEFAULT_KEYLENGTH ], iv[ GOST::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, GOST::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, GOST::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<GOST>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<GOST>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "IDEA" )
  {
    byte key[ IDEA::DEFAULT_KEYLENGTH ], iv[ IDEA::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, IDEA::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, IDEA::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<IDEA>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<IDEA>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "MARS" )
  {
    byte key[ MARS::DEFAULT_KEYLENGTH ], iv[ MARS::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, MARS::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, MARS::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<MARS>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<MARS>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "Panama" )
  {
    byte key[ PanamaCipher<LittleEndian>::DEFAULT_KEYLENGTH ], iv[ PanamaCipher<LittleEndian>::IV_LENGTH ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, PanamaCipher<LittleEndian>::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, PanamaCipher<LittleEndian>::IV_LENGTH );

    if ( encrypt )
    {
      PanamaCipher<LittleEndian>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        PanamaCipher<LittleEndian>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "RC2" )
  {
    byte key[ RC2::DEFAULT_KEYLENGTH ], iv[ RC2::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, RC2::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, RC2::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<RC2>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<RC2>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "RC5" )
  {
    byte key[ RC5::DEFAULT_KEYLENGTH ], iv[ RC5::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, RC5::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, RC5::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<RC5>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<RC5>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "RC6" )
  {
    byte key[ RC6::DEFAULT_KEYLENGTH ], iv[ RC6::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, RC6::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, RC6::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<RC6>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<RC6>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "SAFER_K" )
  {
    byte key[ SAFER_K::DEFAULT_KEYLENGTH ], iv[ SAFER_K::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, SAFER_K::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, SAFER_K::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<SAFER_K>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<SAFER_K>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "SAFER_SK" )
  {
    byte key[ SAFER_SK::DEFAULT_KEYLENGTH ], iv[ SAFER_SK::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, SAFER_SK::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, SAFER_SK::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<SAFER_SK>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<SAFER_SK>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "Salsa20" )
  {
    byte key[ Salsa20::DEFAULT_KEYLENGTH ], iv[ Salsa20::IV_LENGTH ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, Salsa20::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, Salsa20::IV_LENGTH );

    if ( encrypt )
    {
      Salsa20::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        Salsa20::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "SEAL" )
  {
    byte key[ SEAL<BigEndian>::DEFAULT_KEYLENGTH ], iv[ SEAL<BigEndian>::IV_LENGTH ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, SEAL<BigEndian>::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, SEAL<BigEndian>::IV_LENGTH );

    if ( encrypt )
    {
      SEAL<BigEndian>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        SEAL<BigEndian>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "SEED" )
  {
    byte key[ SEED::DEFAULT_KEYLENGTH ], iv[ SEED::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, SEED::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, SEED::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<SEED>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<SEED>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "Serpent" )
  {
    byte key[ Serpent::DEFAULT_KEYLENGTH ], iv[ Serpent::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, Serpent::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, Serpent::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<Serpent>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<Serpent>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "SHACAL2" )
  {
    byte key[ SHACAL2::DEFAULT_KEYLENGTH ], iv[ SHACAL2::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, SHACAL2::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, SHACAL2::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<SHACAL2>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<SHACAL2>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "SHARK" )
  {
    byte key[ SHARK::DEFAULT_KEYLENGTH ], iv[ SHARK::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, SHARK::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, SHARK::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<SHARK>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<SHARK>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "SKIPJACK" )
  {
    byte key[ SKIPJACK::DEFAULT_KEYLENGTH ], iv[ SKIPJACK::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, SKIPJACK::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, SKIPJACK::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<SKIPJACK>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<SKIPJACK>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "Sosemanuk" )
  {
    byte key[ Sosemanuk::DEFAULT_KEYLENGTH ], iv[ Sosemanuk::IV_LENGTH ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, Sosemanuk::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, Sosemanuk::IV_LENGTH );

    if ( encrypt )
    {
      Sosemanuk::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        Sosemanuk::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "Square" )
  {
    byte key[ Square::DEFAULT_KEYLENGTH ], iv[ Square::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, Square::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, Square::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<Square>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<Square>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "TEA" )
  {
    byte key[ TEA::DEFAULT_KEYLENGTH ], iv[ TEA::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, TEA::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, TEA::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<TEA>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<TEA>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "ThreeWay" )
  {
    byte key[ ThreeWay::DEFAULT_KEYLENGTH ], iv[ ThreeWay::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, ThreeWay::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, ThreeWay::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<ThreeWay>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<ThreeWay>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "Twofish" )
  {
    byte key[ Twofish::DEFAULT_KEYLENGTH ], iv[ Twofish::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, Twofish::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, Twofish::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<Twofish>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<Twofish>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "XSalsa20" )
  {
    byte key[ XSalsa20::DEFAULT_KEYLENGTH ], iv[ XSalsa20::IV_LENGTH ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, XSalsa20::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, XSalsa20::IV_LENGTH );

    if ( encrypt )
    {
      XSalsa20::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        XSalsa20::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  else if ( cipher == "XTEA" )
  {
    byte key[ XTEA::DEFAULT_KEYLENGTH ], iv[ XTEA::BLOCKSIZE ];
    StringSource( reinterpret_cast<const char*>( pass.c_str() ), true, new HashFilter( *( new SHA256 ), new ArraySink( key, XTEA::DEFAULT_KEYLENGTH ) ) );
    memset( iv, 0x00, XTEA::BLOCKSIZE );

    if ( encrypt )
    {
      CBC_Mode<XTEA>::Encryption Encryptor( key, sizeof( key ), iv );
      StringSource( text, true, new StreamTransformationFilter( Encryptor, new HexEncoder( new StringSink( CipherText ) ) ) );
    }
    else
    {
      try
      {
        CBC_Mode<XTEA>::Decryption Decryptor( key, sizeof( key ), iv );
        StringSource( text, true, new HexDecoder( new StreamTransformationFilter( Decryptor, new StringSink( RecoveredText ) ) ) );
      }
      catch ( Exception& e )
      {
        return e.what();
      }
      catch ( ... )
      {
        return "Unknown Error";
      }
    }
  }

  if ( encrypt )
    return CipherText;

  return RecoveredText;
}
