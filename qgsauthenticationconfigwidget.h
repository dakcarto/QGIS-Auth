#ifndef QGSAUTHENTICATIONCINFIGWIDGET_H
#define QGSAUTHENTICATIONCINFIGWIDGET_H

#include <QWidget>

#include "ui_qgsauthenticationconfigwidget.h"


class QgsAuthConfigWidget : public QWidget, private Ui::QgsAuthConfigWidget
{
    Q_OBJECT

  public:
    explicit QgsAuthConfigWidget( QWidget *parent = 0 );
    ~QgsAuthConfigWidget();

  private:

};

#endif // QGSAUTHENTICATIONCINFIGWIDGET_H
