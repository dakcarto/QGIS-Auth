/***************************************************************************
    qgsauthenticationcerttrustpolicycombobox.h
    ---------------------
    begin                : May 02, 2015
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

#ifndef QGSAUTHENTICATIONCERTTRUSTPOLICYCOMBOBOX_H
#define QGSAUTHENTICATIONCERTTRUSTPOLICYCOMBOBOX_H

#include <QComboBox>
#include "qgsauthenticationcertutils.h"

class GUI_EXPORT QgsAuthCertTrustPolicyComboBox : public QComboBox
{
    Q_OBJECT

  public:
    explicit QgsAuthCertTrustPolicyComboBox(
        QWidget *parent = 0,
        QgsAuthCertUtils::CertTrustPolicy policy = QgsAuthCertUtils::DefaultTrust,
        QgsAuthCertUtils::CertTrustPolicy defaultpolicy =  QgsAuthCertUtils::DefaultTrust );
    ~QgsAuthCertTrustPolicyComboBox();

    QgsAuthCertUtils::CertTrustPolicy trustPolicy();
    QgsAuthCertUtils::CertTrustPolicy trustPolicyForIndex( int indx );

  public slots:
    void setTrustPolicy( QgsAuthCertUtils::CertTrustPolicy policy );

    void setDefaultTrustPolicy( QgsAuthCertUtils::CertTrustPolicy defaultpolicy );

  private slots:
    void highlightCurrentIndex( int indx );

  private:
    const QString defaultTrustText(
        QgsAuthCertUtils::CertTrustPolicy defaultpolicy =  QgsAuthCertUtils::DefaultTrust );
};

#endif // QGSAUTHENTICATIONCERTTRUSTPOLICYCOMBOBOX_H
