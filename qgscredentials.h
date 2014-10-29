#ifndef QGSCREDENTIALS_H
#define QGSCREDENTIALS_H

#include <QObject>
#include <QMutex>

class QgsCredentials : public QObject
{
    Q_OBJECT
  public:
    QgsCredentials();

    static QgsCredentials *instance();

    bool getMasterPassword( QString *password, bool stored = false );

    void lock();
    void unlock();

  private:
    static QgsCredentials *smInstance;
    QMutex mMutex;
};

#endif // QGSCREDENTIALS_H
