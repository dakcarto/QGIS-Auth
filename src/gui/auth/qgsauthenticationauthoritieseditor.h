/***************************************************************************
    qgsauthenticationauthoritieseditor.h
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

#ifndef QGSAUTHENTICATIONAUTHORITIESEDITOR_H
#define QGSAUTHENTICATIONAUTHORITIESEDITOR_H

#include <QWidget>
#include <QSslCertificate>

#include "ui_qgsauthenticationauthoritieseditor.h"
#include "qgsauthenticationmanager.h"

class QgsMessageBar;
class QMenu;
class QAction;

/** \ingroup gui
 * Widget for viewing and editing authentication identities database
 * \since 2.9
 */
class GUI_EXPORT QgsAuthAuthoritiesEditor : public QWidget, private Ui::QgsAuthAuthoritiesEditor
{
    Q_OBJECT

  public:
    enum CaType
    {
      Section = 1000,
      OrgName = 1001,
      RootCaCert = 1002,
      FileCaCert = 1003,
      DbCaCert = 1004,
    };

    /**
     * Widget for viewing and editing certificate authorities directly in database
     */
    explicit QgsAuthAuthoritiesEditor( QWidget *parent = 0 );
    ~QgsAuthAuthoritiesEditor();

    /** Hide the widget's title, e.g. when embedding */
    void toggleTitleVisibility( bool visible );

  private slots:
    void populateCaCertsView();

    void refreshCaCertsView();

    void showCertInfo( QTreeWidgetItem *item );

    /** Pass selection change on to UI update */
    void selectionChanged( const QItemSelection& selected, const QItemSelection& deselected );

    /** Update UI based upon current selection */
    void checkSelection();

    void handleDoubleClick( QTreeWidgetItem* item, int col );

    void on_btnAddCa_clicked();

    void on_btnRemoveCa_clicked();

    void on_btnInfoCa_clicked();

    void on_btnGroupByOrg_toggled( bool checked );

    void editDefaultTrustPolicy();

    void defaultTrustPolicyChanged( QgsAuthCertUtils::CertTrustPolicy trustpolicy );

    void on_btnCaFile_clicked();

    void on_btnCaFileClear_clicked();

    /** Relay messages to widget's messagebar */
    void authMessageOut( const QString& message, const QString& authtag, QgsAuthManager::MessageLevel level );

  protected:
    void showEvent( QShowEvent *e);

  private:
    void setupCaCertsTree();

    void populateDatabaseCaCerts();

    void populateFileCaCerts();

    void populateRootCaCerts();

    void populateCaCertsSection( QTreeWidgetItem *item, QList<QSslCertificate> certs,
                                 QgsAuthAuthoritiesEditor::CaType catype );

    void appendCertsToGroup( QList<QSslCertificate> certs,
                             QgsAuthAuthoritiesEditor::CaType catype,
                             QTreeWidgetItem *parent = 0 );

    void appendCertsToItem( QList<QSslCertificate> certs,
                            QgsAuthAuthoritiesEditor::CaType catype,
                            QTreeWidgetItem *parent = 0 );

    void updateCertTrustPolicyCache();

    void populateUtilitiesMenu();

    QgsMessageBar * messageBar();
    int messageTimeout();

    QVBoxLayout *mAuthNotifyLayout;
    QLabel *mAuthNotify;

    QTreeWidgetItem * mRootCaSecItem;
    QTreeWidgetItem * mFileCaSecItem;
    QTreeWidgetItem * mDbCaSecItem;

    QgsAuthCertUtils::CertTrustPolicy mDefaultTrustPolicy;
    QMap<QgsAuthCertUtils::CertTrustPolicy, QStringList > mCertTrustCache;

    QMenu * mUtilitiesMenu;
    QAction * mActionDefaultTrustPolicy;
};

#endif // QGSAUTHENTICATIONAUTHORITIESEDITOR_H
