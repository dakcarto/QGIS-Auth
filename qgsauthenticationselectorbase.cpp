#include "qgsauthenticationselectorbase.h"
#include "ui_qgsauthenticationselectorbase.h"

QgsAuthenticationSelectorBase::QgsAuthenticationSelectorBase(QWidget *parent) :
  QWidget(parent),
  ui(new Ui::QgsAuthenticationSelectorBase)
{
  ui->setupUi(this);
}

QgsAuthenticationSelectorBase::~QgsAuthenticationSelectorBase()
{
  delete ui;
}
