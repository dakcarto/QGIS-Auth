/***************************************************************************
    qgsauthenticationimportidentitydialog.cpp
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

#ifndef QGSAUTHENTICATIONIMPORTIDENTITYDIALOG_H
#define QGSAUTHENTICATIONIMPORTIDENTITYDIALOG_H

#include <QDialog>
#include "ui_qgsauthenticationimportidentitydialog.h"

#include <QSslCertificate>
#include <QSslKey>


class GUI_EXPORT QgsAuthImportIdentityDialog : public QDialog, private Ui::QgsAuthImportIdentityDialog
{
    Q_OBJECT

  public:
    enum IdentityType
    {
      CertIdentity = 0,
    };

    explicit QgsAuthImportIdentityDialog( QWidget *parent = 0 );
    ~QgsAuthImportIdentityDialog();

    QgsAuthImportIdentityDialog::IdentityType identityType() { return mIdentityType; }

    const QPair<QSslCertificate, QSslKey> certBundleToImport() { return mCertBundle; }

  private:


    QgsAuthImportIdentityDialog::IdentityType  mIdentityType;
    QPair<QSslCertificate, QSslKey> mCertBundle;
};

#endif // QGSAUTHENTICATIONIMPORTIDENTITYDIALOG_H
