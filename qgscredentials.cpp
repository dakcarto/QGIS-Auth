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

bool QgsCredentials::getMasterPassword( QString &password , bool stored )
{
  Q_UNUSED( stored );
  bool ok = false;
  QString text = QInputDialog::getText( 0, tr( "Unlock authentication database" ),
                                        tr( "Master password:" ), QLineEdit::Password,
                                        "", &ok );
  if ( ok && !text.isEmpty() )
  {
    password = text;
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
