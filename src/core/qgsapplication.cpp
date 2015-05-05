#include "qgsapplication.h"

#include <QDir>

QgsApplication::QgsApplication()
{
}

const QString QgsApplication::qgisAuthDbFilePath()
{
  return QString( QDir::homePath() + "/.qgis2/qgis-auth.db" );
}

QIcon QgsApplication::getThemeIcon( const QString &theName )
{
  QString myDefaultPath = QString( ":/images/themes/default" ) + QDir::separator() + theName;
  if ( QFile::exists( myDefaultPath ) )
  {
    //could still return an empty icon if it
    //doesnt exist in the default theme either!
    return QIcon( myDefaultPath );
  }
  else
  {
    return QIcon();
  }
}
