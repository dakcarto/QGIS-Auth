#include "qgsauthenticationconfigeditor.h"
#include "ui_qgsauthenticationconfigeditor.h"

QgsAuthConfigEditor::QgsAuthConfigEditor( QWidget *parent )
    : QWidget( parent )
{
  setupUi( this );
}

QgsAuthConfigEditor::~QgsAuthConfigEditor()
{
}
