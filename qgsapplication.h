#ifndef QGSAPPLICATION_H
#define QGSAPPLICATION_H

#include <QString>

class QgsApplication
{
  public:
    QgsApplication();

    //! Returns the path to the user authentication database file: qgis-auth.db.
    static const QString qgisAuthDbFilePath();
};

#endif // QGSAPPLICATION_H
