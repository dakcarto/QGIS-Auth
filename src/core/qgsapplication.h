#ifndef QGSAPPLICATION_H
#define QGSAPPLICATION_H

#include <QString>
#include <QIcon>

class QgsApplication
{
  public:
    QgsApplication();

    //! Returns the path to the settings directory in user's home dir
    static const QString qgisSettingsDirPath();

    //! Returns the path to the user authentication database file: qgis-auth.db.
    static const QString qgisAuthDbFilePath();

    //! Helper to get a theme icon. It will fall back to the
    //! default theme if the active theme does not have the required icon.
    static QIcon getThemeIcon( const QString &theName );
};

#endif // QGSAPPLICATION_H
