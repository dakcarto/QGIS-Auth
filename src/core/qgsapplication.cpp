#include "qgsapplication.h"

#include <QDir>

QgsApplication::QgsApplication()
{
}

const QString QgsApplication::qgisAuthDbFilePath()
{
  return QString( QDir::homePath() + "/.qgis2/qgis-auth.db" );
}
