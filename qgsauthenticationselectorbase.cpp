#include "qgsauthenticationselectorbase.h"
#include "ui_qgsauthenticationselectorbase.h"

QgsAuthSelectorBase::QgsAuthSelectorBase( QWidget *parent )
    : QWidget( parent )
{
  setupUi( this );
}

QgsAuthSelectorBase::~QgsAuthSelectorBase()
{
}
