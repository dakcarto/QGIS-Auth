/***************************************************************************
    qgsauthenticationtrustedcasdialog.h
    ---------------------
    begin                : May 9, 2015
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

#ifndef QGSAUTHENTICATIONTRUSTEDCASDIALOG_H
#define QGSAUTHENTICATIONTRUSTEDCASDIALOG_H

#include <QDialog>
#include "ui_qgsauthenticationtrustedcasdialog.h"

#include <QSslCertificate>

#include "qgsauthenticationmanager.h"

class QgsMessageBar;


class GUI_EXPORT QgsAuthTrustedCAsDialog : public QDialog, private Ui::QgsAuthTrustedCAsDialog
{
    Q_OBJECT

  public:
    enum CaType
    {
      Section = 1000,
      OrgName = 1001,
      CaCert = 1002,
    };

    explicit QgsAuthTrustedCAsDialog( QWidget *parent = 0 );
    ~QgsAuthTrustedCAsDialog();

  private slots:
    void populateCaCertsView();

    void showCertInfo( QTreeWidgetItem *item );

    /** Pass selection change on to UI update */
    void selectionChanged( const QItemSelection& selected, const QItemSelection& deselected );

    /** Update UI based upon current selection */
    void checkSelection();

    void handleDoubleClick( QTreeWidgetItem* item, int col );

    void on_btnInfoCa_clicked();

    void on_btnGroupByOrg_toggled( bool checked );

    /** Relay messages to widget's messagebar */
    void authMessageOut( const QString& message, const QString& authtag, QgsAuthManager::MessageLevel level );

  protected:
    void showEvent( QShowEvent *e);

  private:
    void setupCaCertsTree();

    void populateCaCertsSection( QTreeWidgetItem *item, QList<QSslCertificate> certs,
                                 QgsAuthTrustedCAsDialog::CaType catype );

    void appendCertsToGroup( QList<QSslCertificate> certs,
                             QgsAuthTrustedCAsDialog::CaType catype,
                             QTreeWidgetItem *parent = 0 );

    void appendCertsToItem( QList<QSslCertificate> certs,
                            QgsAuthTrustedCAsDialog::CaType catype,
                            QTreeWidgetItem *parent = 0 );

    QgsMessageBar * messageBar();
    int messageTimeout();

    QVBoxLayout *mAuthNotifyLayout;
    QLabel *mAuthNotify;

    QTreeWidgetItem * mRootCaSecItem;
};

#endif // QGSAUTHENTICATIONTRUSTEDCASDIALOG_H
