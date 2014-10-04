#include "qgscredentials.h"

#include <QInputDialog>

#include "qgsauthenticationmanager.h"

QgsCredentials::QgsCredentials()
    : QObject()
{
}

QgsCredentials *QgsCredentials::smInstance = 0;

QgsCredentials *QgsCredentials::instance()
{
  if ( !smInstance )
  {
    smInstance = new QgsCredentials();
  }
  return smInstance;
}

bool QgsCredentials::getMasterPassword( QString *password )
{
  bool ok = false;
  QString text = QInputDialog::getText( 0, tr( "Unlock authentication database" ),
                                        tr( "Master password:" ), QLineEdit::Password,
                                        "", &ok );
  if ( ok && !text.isEmpty() )
  {
    *password = text;
  }
  return ok;
}

bool QgsCredentials::getMasterResetPassword( QString *newpass )
{
  bool ok = false;
  while ( true )
  {
    // TODO: Always verify master password first, then only activate widgets for password reset on VERIFIED current password
    // "This will cause your authentication database to be duplicated and completely rebuilt using new password."
    QString text = QInputDialog::getText( 0, tr( "Unlock authentication database" ),
                                          tr( "New master password:" ), QLineEdit::Password,
                                          "", &ok );
    if ( !ok )
    {
      break;
    }

    if ( ok && !text.isEmpty() && !QgsAuthManager::instance()->masterPasswordSame( text ) )
    {
      *newpass = text;
      break;
    }
  }
  return ok;
}

void QgsCredentials::lock()
{
  mMutex.lock();
}

void QgsCredentials::unlock()
{
  mMutex.unlock();
}
