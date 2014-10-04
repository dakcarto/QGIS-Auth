#include "qgsauthenticationselectorbase.h"
#include "ui_qgsauthenticationselectorbase.h"

QgsAuthSelectorBase::QgsAuthSelectorBase( QWidget *parent ) :
    QWidget( parent ),
    ui( new Ui::QgsAuthSelectorBase )
{
  ui->setupUi( this );
}

QgsAuthSelectorBase::~QgsAuthSelectorBase()
{
  delete ui;
}
