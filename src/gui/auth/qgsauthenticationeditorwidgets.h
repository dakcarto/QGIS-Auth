#ifndef QGSAUTHENTICATIONEDITORWIDGETS_H
#define QGSAUTHENTICATIONEDITORWIDGETS_H

#include <QWidget>
#include "ui_qgsauthenticationeditorwidgets.h"


class QgsAuthEditorWidgets : public QWidget, private Ui::QgsAuthEditors
{
    Q_OBJECT

  public:
    explicit QgsAuthEditorWidgets( QWidget *parent = 0 ) :
      QWidget( parent )
    {
      setupUi( this );
    }

    ~QgsAuthEditorWidgets(){}

  private:

};

#endif // QGSAUTHENTICATIONEDITORWIDGETS_H
