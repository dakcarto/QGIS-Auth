#ifndef QGSAUTHENTICATIONCONFIGSELECT_H
#define QGSAUTHENTICATIONCONFIGSELECT_H

#include <QWidget>

#include "ui_qgsauthenticationconfigselect.h"

class QgsAuthConfigSelect : public QWidget, private Ui::QgsAuthConfigSelect
{
    Q_OBJECT

  public:
    explicit QgsAuthConfigSelect(QWidget *parent = 0);
    ~QgsAuthConfigSelect();

  private:
};

#endif // QGSAUTHENTICATIONCONFIGSELECT_H
