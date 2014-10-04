#ifndef QGSAUTHENTICATIONWIDGETBASE_H
#define QGSAUTHENTICATIONWIDGETBASE_H

#include <QWidget>

#include "ui_qgsauthenticationwidgetbase.h"


class QgsAuthWidgetBase : public QWidget, private Ui::QgsAuthWidgetBase
{
    Q_OBJECT

  public:
    explicit QgsAuthWidgetBase( QWidget *parent = 0 );
    ~QgsAuthWidgetBase();

  private:

};

#endif // QGSAUTHENTICATIONWIDGETBASE_H
