#include "qgsauthenticationconfigeditor.h"
#include "ui_qgsauthenticationconfigeditor.h"

#include <QMessageBox>
#include <QSqlTableModel>

#include "qgsauthenticationmanager.h"
#include "qgsauthenticationconfigwidget.h"

QgsAuthConfigEditor::QgsAuthConfigEditor( QWidget *parent )
    : QWidget( parent )
    , mConfigModel( 0 )
{
  setupUi( this );

  mConfigModel = new QSqlTableModel( this, QgsAuthManager::instance()->authDbConnection() );
  mConfigModel->setTable( QgsAuthManager::instance()->authDbConfigTable() );
  mConfigModel->select();

  mConfigModel->setHeaderData( 0, Qt::Horizontal, tr( "ID" ) );
  mConfigModel->setHeaderData( 1, Qt::Horizontal, tr( "Name" ) );
  mConfigModel->setHeaderData( 2, Qt::Horizontal, tr( "URI" ) );
  mConfigModel->setHeaderData( 3, Qt::Horizontal, tr( "Type" ) );
  mConfigModel->setHeaderData( 4, Qt::Horizontal, tr( "Version" ) );
  mConfigModel->setHeaderData( 5, Qt::Horizontal, tr( "Config" ) );

  tableViewConfigs->setModel( mConfigModel );
  tableViewConfigs->resizeColumnsToContents();
//  tableViewConfigs->resizeColumnToContents( 0 );
//  tableViewConfigs->horizontalHeader()->setResizeMode(1, QHeaderView::Stretch);
//  tableViewConfigs->horizontalHeader()->setResizeMode(2, QHeaderView::Interactive);
//  tableViewConfigs->resizeColumnToContents( 3 );
  tableViewConfigs->hideColumn( 4 );
  tableViewConfigs->hideColumn( 5 );

  connect( tableViewConfigs->selectionModel(), SIGNAL( selectionChanged( const QItemSelection&, const QItemSelection& ) ),
           this, SLOT( selectionChanged( const QItemSelection&, const QItemSelection& ) ) );

  connect( tableViewConfigs, SIGNAL( doubleClicked( QModelIndex ) ),
           this, SLOT( on_btnEditConfig_clicked() ) );

  checkSelection();
}

QgsAuthConfigEditor::~QgsAuthConfigEditor()
{
}

void QgsAuthConfigEditor::selectionChanged( const QItemSelection& selected , const QItemSelection& deselected )
{
  Q_UNUSED( selected );
  Q_UNUSED( deselected );
  checkSelection();
}

void QgsAuthConfigEditor::checkSelection()
{
  bool hasselection = tableViewConfigs->selectionModel()->selection().length() > 0;
  btnEditConfig->setEnabled( hasselection );
  btnRemoveConfig->setEnabled( hasselection );
}

void QgsAuthConfigEditor::on_btnAddConfig_clicked()
{
  if ( !QgsAuthManager::instance()->setMasterPassword( true ) )
    return;

  QgsAuthConfigWidget * aw = new QgsAuthConfigWidget( this );
  aw->setWindowModality( Qt::WindowModal );
  if ( aw->exec() )
  {
    mConfigModel->select();
  }
}

void QgsAuthConfigEditor::on_btnEditConfig_clicked()
{
  QString authid = selectedConfigId();

  if ( authid.isEmpty() )
    return;

  if ( !QgsAuthManager::instance()->setMasterPassword( true ) )
    return;

  QgsAuthConfigWidget * aw = new QgsAuthConfigWidget( this, authid );
  aw->setWindowModality( Qt::WindowModal );
  if ( aw->exec() )
  {
    mConfigModel->select();
  }
}

void QgsAuthConfigEditor::on_btnRemoveConfig_clicked()
{
  QModelIndexList selection = tableViewConfigs->selectionModel()->selectedRows( 0 );

  if ( selection.empty() )
    return;

  QModelIndex indx = selection.at( 0 );
  QString name = indx.sibling( indx.row(), 1 ).data().toString();

  if ( QMessageBox::warning( this, tr( "Remove Configuration" ),
                             tr( "Are you sure you want to remove '%1'? (no undo)" ).arg( name ),
                             QMessageBox::Yes | QMessageBox::No ) == QMessageBox::Yes )
  {
    mConfigModel->removeRow( indx.row() );
  }
}

QString QgsAuthConfigEditor::selectedConfigId()
{
  QModelIndexList selection = tableViewConfigs->selectionModel()->selectedRows( 0 );

  if ( selection.empty() )
    return QString();

  QModelIndex indx = selection.at( 0 );
  return indx.sibling( indx.row(), 0 ).data().toString();
}
