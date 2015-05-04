/***************************************************************************
    qgsauthenticationidentitieseditor.h
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

#ifndef QGSAUTHENTICATIONIDENTITIESEDITOR_H
#define QGSAUTHENTICATIONIDENTITIESEDITOR_H

#include <QWidget>

#include "ui_qgsauthenticationidentitieseditor.h"
#include "qgsauthenticationmanager.h"

class QgsMessageBar;

/** \ingroup gui
 * Widget for viewing and editing authentication identities database
 * \since 2.9
 */
class GUI_EXPORT QgsAuthIdentitiesEditor : public QWidget, private Ui::QgsAuthIdentitiesEditor
{
    Q_OBJECT

  public:
    /**
     * Widget for editing authentication configurations directly in database
     */
    explicit QgsAuthIdentitiesEditor( QWidget *parent = 0 );
    ~QgsAuthIdentitiesEditor();

    /** Hide the widget's title, e.g. when embedding */
    void toggleTitleVisibility( bool visible );

  private slots:
    /** Relay messages to widget's messagebar */
    void authMessageOut( const QString& message, const QString& authtag, QgsAuthManager::MessageLevel level );

    /** Pass selection change on to UI update */
    void selectionChanged( const QItemSelection& selected, const QItemSelection& deselected );

    /** Update UI based upon current selection */
    void checkSelection();

    void on_btnAddIdentity_clicked();

    void on_btnRemoveIdentity_clicked();

    void on_btnInfoIdentity_clicked();

  private:
    QgsMessageBar * messageBar();
    int messageTimeout();

    QVBoxLayout *mAuthNotifyLayout;
    QLabel *mAuthNotify;
};

#endif // QGSAUTHENTICATIONIDENTITIESEDITOR_H
