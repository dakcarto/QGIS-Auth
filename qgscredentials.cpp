#include "qgscredentials.h"

#include <QInputDialog>

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
  QString text = QInputDialog::getText( 0, tr( "QInputDialog::getText()" ),
                                        tr( "Master password:" ), QLineEdit::Password,
                                        "", &ok );
  if ( ok && !text.isEmpty() )
  {
    *password = text;
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
