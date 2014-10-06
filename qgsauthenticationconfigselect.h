#ifndef QGSAUTHENTICATIONCONFIGSELECT_H
#define QGSAUTHENTICATIONCONFIGSELECT_H

#include <QWidget>

#include "ui_qgsauthenticationconfigselect.h"
#include "qgsauthenticationconfig.h"

class QgsAuthConfigSelect : public QWidget, private Ui::QgsAuthConfigSelect
{
    Q_OBJECT

  public:
    explicit QgsAuthConfigSelect( QWidget *parent = 0 );
    ~QgsAuthConfigSelect();

    void setConfigId( const QString& authid );
    const QString configId() const { return mConfigId; }

  private slots:
    void loadConfig();
    void clearConfig();
    void validateConfig();
    void populateConfigSelector();

    void on_cmbConfigSelect_currentIndexChanged( int index );

    void on_btnConfigAdd_clicked();

    void on_btnConfigEdit_clicked();

    void on_btnConfigRemove_clicked();

  private:
    void loadAvailableConfigs();

    QString mConfigId;
    QHash<QString, QgsAuthConfigBase> mConfigs;
};

#endif // QGSAUTHENTICATIONCONFIGSELECT_H
