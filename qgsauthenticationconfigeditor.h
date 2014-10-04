#ifndef QGSAUTHENTICATIONCONFIGEDITOR_H
#define QGSAUTHENTICATIONCONFIGEDITOR_H

#include <QWidget>

#include "ui_qgsauthenticationconfigeditor.h"

class QgsAuthConfigEditor : public QWidget, private Ui::QgsAuthConfigEditor
{
    Q_OBJECT

  public:
    explicit QgsAuthConfigEditor( QWidget *parent = 0 );
    ~QgsAuthConfigEditor();

  private:
};

#endif // QGSAUTHENTICATIONCONFIGEDITOR_H
