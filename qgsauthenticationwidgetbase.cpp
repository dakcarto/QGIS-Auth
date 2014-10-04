#include "qgsauthenticationwidgetbase.h"
#include "ui_qgsauthenticationwidgetbase.h"

QgsAuthWidgetBase::QgsAuthWidgetBase( QWidget *parent )
    : QWidget( parent )
{
  setupUi( this );
}

QgsAuthWidgetBase::~QgsAuthWidgetBase()
{
}
