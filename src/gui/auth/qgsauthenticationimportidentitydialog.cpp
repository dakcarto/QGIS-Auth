/***************************************************************************
    qgsauthenticationimportidentitydialog.h
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

#include "qgsauthenticationimportidentitydialog.h"
#include "ui_qgsauthenticationimportidentitydialog.h"


QgsAuthImportIdentityDialog::QgsAuthImportIdentityDialog( QWidget *parent )
  : QDialog( parent )
{
  setupUi( this );
  mIdentityType = CertIdentity;
}

QgsAuthImportIdentityDialog::~QgsAuthImportIdentityDialog()
{
}
