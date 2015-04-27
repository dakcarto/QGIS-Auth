/***************************************************************************
    qgsauthenticationserverseditor.h
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

#ifndef QGSAUTHENTICATIONSERVERSEDITOR_H
#define QGSAUTHENTICATIONSERVERSEDITOR_H

#include <QWidget>

#include "ui_qgsauthenticationserverseditor.h"
#include "qgsauthenticationmanager.h"

class QgsMessageBar;

/** \ingroup gui
 * Widget for viewing and editing servers in authentication database
 * \since 2.9
 */
class GUI_EXPORT QgsAuthServersEditor : public QWidget, private Ui::QgsAuthServersEditor
{
    Q_OBJECT

  public:
    /**
     * Widget for editing authentication configurations directly in database
     */
    explicit QgsAuthServersEditor( QWidget *parent = 0 );
    ~QgsAuthServersEditor();

    /** Hide the widget's title, e.g. when embedding */
    void toggleTitleVisibility( bool visible );

  private slots:
    /** Relay messages to widget's messagebar */
    void authMessageOut( const QString& message, const QString& authtag, QgsAuthManager::MessageLevel level );

    /** Pass selection change on to UI update */
    void selectionChanged( const QItemSelection& selected, const QItemSelection& deselected );

    /** Update UI based upon current selection */
    void checkSelection();

    void on_btnAddServer_clicked();

    void on_btnRemoveServer_clicked();

    void on_btnInfoServer_clicked();

  private:
    QgsMessageBar * messageBar();
    int messageTimeout();
    QString selectedId();

    QVBoxLayout *mAuthNotifyLayout;
    QLabel *mAuthNotify;
};

#endif // QGSAUTHENTICATIONSERVERSEDITOR_H
