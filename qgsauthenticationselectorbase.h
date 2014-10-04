#ifndef QGSAUTHENTICATIONSELECTORBASE_H
#define QGSAUTHENTICATIONSELECTORBASE_H

#include <QWidget>

#include "ui_qgsauthenticationselectorbase.h"

class QgsAuthSelectorBase : public QWidget, private Ui::QgsAuthSelectorBase
{
    Q_OBJECT

  public:
    explicit QgsAuthSelectorBase( QWidget *parent = 0 );
    ~QgsAuthSelectorBase();

  private:
    Ui::QgsAuthSelectorBase *ui;
};

#endif // QGSAUTHENTICATIONSELECTORBASE_H
