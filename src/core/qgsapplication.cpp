#include "qgsapplication.h"
#include "qgis.h"

#include <QDir>

QgsApplication::QgsApplication()
{
}

const QString QgsApplication::qgisSettingsDirPath()
{
//  return QString( QDir::homePath() + "/.qgis2/" );

  return QString( "%1/.qgis%2/" ).arg( QDir::homePath() ).arg( QGis::QGIS_VERSION_INT / 10000 );
}

const QString QgsApplication::qgisAuthDbFilePath()
{
  return QString( QgsApplication::qgisSettingsDirPath() + "qgis-auth.db" );
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
