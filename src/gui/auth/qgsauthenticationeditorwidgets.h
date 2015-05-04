#ifndef QGSAUTHENTICATIONEDITORWIDGETS_H
#define QGSAUTHENTICATIONEDITORWIDGETS_H

#include <QWidget>
#include "ui_qgsauthenticationeditorwidgets.h"

class QTabWidget;

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

    QTabWidget * tabbedWidget() { return tabWidget; }

  private:

};

#endif // QGSAUTHENTICATIONEDITORWIDGETS_H
