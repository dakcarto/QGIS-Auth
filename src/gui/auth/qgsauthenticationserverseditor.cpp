/***************************************************************************
    qgsauthenticationserverseditor.cpp
    ---------------------
    begin                : April 26, 2015
    copyright            : (C) 2015 by Boundless Spatial, Inc. USA
    author               : Larry Shaffer
    email                : lshaffer at boundlessgeo dot com
 ***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include "qgsauthenticationserverseditor.h"
#include "ui_qgsauthenticationserverseditor.h"

#include <QMenu>
#include <QMessageBox>
#include <QSettings>

#include "qgsauthenticationmanager.h"
#include "qgsauthenticationutils.h"

QgsAuthServersEditor::QgsAuthServersEditor( QWidget *parent )
    : QWidget( parent )
    , mAuthNotifyLayout( 0 )
    , mAuthNotify( 0 )
{
  if ( QgsAuthManager::instance()->isDisabled() )
  {
    mAuthNotifyLayout = new QVBoxLayout;
    this->setLayout( mAuthNotifyLayout );
    mAuthNotify = new QLabel( QgsAuthManager::instance()->disabledMessage(), this );
    mAuthNotifyLayout->addWidget( mAuthNotify );
  }
  else
  {
    setupUi( this );

//    connect( tableViewConfigs->selectionModel(), SIGNAL( selectionChanged( const QItemSelection&, const QItemSelection& ) ),
//             this, SLOT( selectionChanged( const QItemSelection&, const QItemSelection& ) ) );

//    connect( tableViewConfigs, SIGNAL( doubleClicked( QModelIndex ) ),
//             this, SLOT( on_btnEditConfig_clicked() ) );

    connect( QgsAuthManager::instance(), SIGNAL( messageOut( const QString&, const QString&, QgsAuthManager::MessageLevel ) ),
             this, SLOT( authMessageOut( const QString&, const QString&, QgsAuthManager::MessageLevel ) ) );

    checkSelection();

  }
}

QgsAuthServersEditor::~QgsAuthServersEditor()
{
}

void QgsAuthServersEditor::authMessageOut( const QString& message, const QString& authtag, QgsAuthManager::MessageLevel level )
{
  int levelint = ( int )level;
  messageBar()->pushMessage( authtag, message, ( QgsMessageBar::MessageLevel )levelint, 7 );
}


void QgsAuthServersEditor::selectionChanged( const QItemSelection& selected , const QItemSelection& deselected )
{
  Q_UNUSED( selected );
  Q_UNUSED( deselected );
  checkSelection();
}

void QgsAuthServersEditor::checkSelection()
{
//  bool hasselection = tableViewConfigs->selectionModel()->selection().length() > 0;
//  btnEditConfig->setEnabled( hasselection );
//  btnRemoveConfig->setEnabled( hasselection );
}

void QgsAuthServersEditor::on_btnAddServer_clicked()
{
//  if ( !QgsAuthManager::instance()->setMasterPassword( true ) )
//    return;

//  QgsAuthConfigWidget * aw = new QgsAuthConfigWidget( this );
//  aw->setWindowModality( Qt::WindowModal );
//  if ( aw->exec() )
//  {
//    mConfigModel->select();
//  }
}

void QgsAuthServersEditor::on_btnInfoServer_clicked()
{
//  QString authcfg = selectedConfigId();

//  if ( authcfg.isEmpty() )
//    return;

//  if ( !QgsAuthManager::instance()->setMasterPassword( true ) )
//    return;

//  QgsAuthConfigWidget * aw = new QgsAuthConfigWidget( this, authcfg );
//  aw->setWindowModality( Qt::WindowModal );
//  if ( aw->exec() )
//  {
//    mConfigModel->select();
//  }
}

void QgsAuthServersEditor::on_btnRemoveServer_clicked()
{
  // get selection count

//  if ( selection.empty() )
//    return;

}

QgsMessageBar * QgsAuthServersEditor::messageBar()
{
  return msgBar;
}

int QgsAuthServersEditor::messageTimeout()
{
  QSettings settings;
  return settings.value( "/qgis/messageTimeout", 5 ).toInt();
}

QString QgsAuthServersEditor::selectedId()
{
  // get selection count

//  if ( selection.empty() )
//    return QString();
}
