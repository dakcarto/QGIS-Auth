/***************************************************************************
    qgsauthenticationconfigeditor.h
    ---------------------
    begin                : October 5, 2014
    copyright            : (C) 2014 by Boundless Spatial, Inc. USA
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

#ifndef QGSAUTHENTICATIONCONFIGEDITOR_H
#define QGSAUTHENTICATIONCONFIGEDITOR_H

#include <QSqlTableModel>
#include <QWidget>

#include "ui_qgsauthenticationconfigeditor.h"
#include "qgsauthenticationmanager.h"

class QgsMessageBar;

/** \ingroup gui
 * Widget for editing authentication configuration database
 * \since 2.8
 */
class GUI_EXPORT QgsAuthConfigEditor : public QWidget, private Ui::QgsAuthConfigEditor
{
    Q_OBJECT

  public:
    /**
     * Widget for editing authentication configurations directly in database
     */
    explicit QgsAuthConfigEditor( QWidget *parent = 0 );
    ~QgsAuthConfigEditor();

    /** Hide the widget's title, e.g. when embedding */
    void toggleTitleVisibility( bool visible );

  private slots:
    /** Sets the cached master password (and verifies it if its hash is in authentication database) */
    void setMasterPassword();

    /** Clear the currently cached master password (not its hash in database) */
    void clearCachedMasterPassword();

    /** Reset the cached master password, updating its hash in authentication database and reseting all existing configs to use it */
    void resetMasterPassword();

    /** Clear all cached authentication configs for session */
    void clearCachedAuthenticationConfigs();

    /** Remove all authentication configs */
    void removeAuthenticationConfigs();

    /** Completely clear out the authentication database (configs and master password) */
    void eraseAuthenticationDatabase();

    /** Relay messages to widget's messagebar */
    void authMessageOut( const QString& message, const QString& authtag, QgsAuthManager::MessageLevel level );

    /** Pass selection change on to UI update */
    void selectionChanged( const QItemSelection& selected, const QItemSelection& deselected );

    /** Update UI based upon current selection */
    void checkSelection();

    void on_btnAddConfig_clicked();

    void on_btnEditConfig_clicked();

    void on_btnRemoveConfig_clicked();

  private:
    QgsMessageBar * messageBar();
    int messageTimeout();
    QString selectedConfigId();

    QSqlTableModel *mConfigModel;

    QMenu *mAuthUtilitiesMenu;
    QAction *mActionSetMasterPassword;
    QAction *mActionClearCachedMasterPassword;
    QAction *mActionResetMasterPassword;
    QAction *mActionClearCachedAuthConfigs;
    QAction *mActionRemoveAuthConfigs;
    QAction *mActionEraseAuthDatabase;

    QVBoxLayout *mAuthNotifyLayout;
    QLabel *mAuthNotify;
};

#endif // QGSAUTHENTICATIONCONFIGEDITOR_H
