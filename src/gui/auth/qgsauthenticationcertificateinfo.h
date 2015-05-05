/***************************************************************************
    qgsauthenticationcertificateinfo.h
    ---------------------
    begin                : April 29, 2015
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


#ifndef QGSAUTHENTICATIONCERTIFICATEINFO_H
#define QGSAUTHENTICATIONCERTIFICATEINFO_H

#ifndef QT_NO_OPENSSL
#include <QtCrypto>
#include <QSslCertificate>
#endif

#include <QWidget>
#include "ui_qgsauthenticationcertificateinfo.h"
#include "qgsauthenticationcertutils.h"


class GUI_EXPORT QgsAuthCertInfo : public QWidget, private Ui::QgsAuthCertInfo
{
    Q_OBJECT

  public:
    explicit QgsAuthCertInfo( QSslCertificate cert, bool manageCertTrust = false, QWidget *parent = 0 );
    ~QgsAuthCertInfo();

    bool trustCacheRebuilt() { return mTrustCacheRebuilt; }

  private slots:
    void setupError( const QString& msg );

    void currentCertItemChanged( QTreeWidgetItem *current, QTreeWidgetItem *previous );

    void updateCurrentCert( QTreeWidgetItem *item );

    void on_btnSaveTrust_clicked();

    void currentPolicyIndexChanged( int indx );

    void decorateCertTreeItem( const QSslCertificate& cert,
                               QgsAuthCertUtils::CertTrustPolicy trustpolicy,
                               QTreeWidgetItem * item = 0 );

  private:
    void populateTrustBox();

    void updateCurrentCertInfo( int chainindx );

    bool populateQcaCertCollection();

    bool setQcaCertificate( QSslCertificate cert );

    bool populateCertChain();

    void setCertHeirarchy();

    QCA::Certificate mCert;
    QMap<QString, QPair<QgsAuthCertUtils::CaCertSource, QSslCertificate> > mCaCertsCache;
    QCA::CertificateCollection mCaCerts;
    QCA::CertificateChain mACertChain;
    QList<QSslCertificate> mQCertChain;
    QSslCertificate mCurrentQCert;
    QCA::Certificate mCurrentACert;

    QBrush mDefaultItemForeground;

    bool mManageTrust;
    bool mTrustCacheRebuilt;
    QgsAuthCertUtils::CertTrustPolicy mDefaultTrustPolicy;
    QgsAuthCertUtils::CertTrustPolicy mCurrentTrustPolicy;
};

#endif // QGSAUTHENTICATIONCERTIFICATEINFO_H