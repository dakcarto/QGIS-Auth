#ifndef QGSAPPLICATION_H
#define QGSAPPLICATION_H

#include <QString>
#include <QIcon>

class QgsApplication
{
  public:
    QgsApplication();

    //! Returns the path to the user authentication database file: qgis-auth.db.
    static const QString qgisAuthDbFilePath();

    //! Helper to get a theme icon. It will fall back to the
    //! default theme if the active theme does not have the required icon.
    static QIcon getThemeIcon( const QString &theName )
    {
      Q_UNUSED(theName);
      return QIcon();
    }
};

#endif // QGSAPPLICATION_H
