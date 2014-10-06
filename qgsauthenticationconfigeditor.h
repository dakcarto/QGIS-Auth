#ifndef QGSAUTHENTICATIONCONFIGEDITOR_H
#define QGSAUTHENTICATIONCONFIGEDITOR_H

#include <QSqlTableModel>
#include <QWidget>

#include "ui_qgsauthenticationconfigeditor.h"

class QgsAuthConfigEditor : public QWidget, private Ui::QgsAuthConfigEditor
{
    Q_OBJECT

  public:
    explicit QgsAuthConfigEditor( QWidget *parent = 0 );
    ~QgsAuthConfigEditor();

  private slots:
    void selectionChanged( const QItemSelection& selected, const QItemSelection& deselected );

    void checkSelection();

    void on_btnAddConfig_clicked();

    void on_btnEditConfig_clicked();

    void on_btnRemoveConfig_clicked();

  private:
    QString selectedConfigId();

    QSqlTableModel *mConfigModel;
};

#endif // QGSAUTHENTICATIONCONFIGEDITOR_H
