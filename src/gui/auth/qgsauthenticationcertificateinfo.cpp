/***************************************************************************
    qgsauthenticationcertificateinfo.cpp
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


#include "qgsauthenticationcertificateinfo.h"
#include "ui_qgsauthenticationcertificateinfo.h"

#include <QtCrypto>

#include "qgsapplication.h"
#include "qgsauthenticationcertutils.h"
#include "qgsauthenticationmanager.h"
#include "qgslogger.h"


QgsAuthCertInfo::QgsAuthCertInfo( QSslCertificate cert, bool manageCertTrust, QWidget *parent )
  : QWidget( parent )
  , mDefaultItemForeground( QBrush() )
  , mManageTrust( manageCertTrust )
  , mTrustCacheRebuilt( false )
{
  setupUi( this );

  lblError->setHidden( true );

  treeHeirarchy->setRootIsDecorated( true );

  connect( treeHeirarchy, SIGNAL( currentItemChanged( QTreeWidgetItem *, QTreeWidgetItem * ) ),
           this, SLOT( currentCertItemChanged( QTreeWidgetItem*, QTreeWidgetItem* ) ) );

  mCaCertsCache = QgsAuthManager::instance()->getCaCertsCache();

  grpbxTrust->setShown( mManageTrust );

  // trust policy is still queried, even if not managing the policy, so public getter will work
  mDefaultTrustPolicy = QgsAuthManager::instance()->defaultCertTrustPolicy();
  mCurrentTrustPolicy = QgsAuthCertUtils::DefaultTrust;

  bool res;
  res = populateQcaCertCollection();
  if ( res )
    res = setQcaCertificate( cert );
  if ( res )
    res = populateCertChain();
  if ( res )
    setCertHeirarchy();

  connect( cmbbxTrust, SIGNAL( currentIndexChanged( int ) ),
           this, SLOT( currentPolicyIndexChanged( int ) ) );
}

QgsAuthCertInfo::~QgsAuthCertInfo()
{
}

void QgsAuthCertInfo::setupError( const QString &msg )
{
  lblError->setShown( true );
  QString out = tr( "<b>Setup ERROR:</b>\n\n" );
  out += msg;
  lblError->setText( out );
  lblError->setStyleSheet( QgsAuthCertUtils::redTextStyleSheet() );
}

void QgsAuthCertInfo::currentCertItemChanged( QTreeWidgetItem *current, QTreeWidgetItem *previous )
{
  Q_UNUSED( previous );
  updateCurrentCert( current );
}

void QgsAuthCertInfo::updateCurrentCert( QTreeWidgetItem *item )
{
  if ( !item )
    item = treeHeirarchy->currentItem();
  if ( !item )
    return;

  int indx( item->data( 0, Qt::UserRole ).toInt() );
  updateCurrentCertInfo( indx );
}

bool QgsAuthCertInfo::populateQcaCertCollection()
{
  const QList<QPair<QgsAuthCertUtils::CaCertSource, QSslCertificate> >& certpairs( mCaCertsCache.values() );
  for (int i = 0; i < certpairs.size(); ++i) {
    QCA::ConvertResult res;
    QCA::Certificate acert = QCA::Certificate::fromPEM( certpairs.at( i ).second.toPem(), &res, QString( "qca-ossl" ) );
    if ( res == QCA::ConvertGood && !acert.isNull() )
    {
      mCaCerts.addCertificate( acert );
    }
  }
  if ( mCaCerts.certificates().size() < 1 )
  {
    setupError( tr( "Could not populate QCA certificate collection" ) );
    return false;
  }
  return true;
}

bool QgsAuthCertInfo::setQcaCertificate( QSslCertificate cert )
{
  QCA::ConvertResult res;
  mCert = QCA::Certificate::fromPEM( cert.toPem(), &res, QString( "qca-ossl" ) );
  if ( res != QCA::ConvertGood || mCert.isNull() )
  {
    setupError( tr( "Could not set QCA certificate" ) );
    return false;
  }
  return true;
}

bool QgsAuthCertInfo::populateCertChain()
{
  QCA::CertificateChain certchain( mCert );
  QCA::Validity valid;
  mACertChain = certchain.complete( mCaCerts.certificates(), &valid );
  if ( valid != QCA::ValidityGood && valid != QCA::ErrorInvalidCA )
  {
    // invalid CAs are skipped to create allow an incomplete chain
    setupError( tr( "Invalid population of QCA certificate chain.<br><br>"
                    "Validity message: %1" ).arg( QgsAuthCertUtils::qcaValidityMessage( valid ) ) );
    return false;
  }

  if ( mACertChain.isEmpty() )
  {
    QgsDebugMsg( "Could not populate QCA certificate chain" );
    mACertChain = certchain;
  }

  // mirror chain to QSsslCertificate
  Q_FOREACH( QCA::Certificate cert, mACertChain )
  {
    QSslCertificate qcert( cert.toPEM().toAscii() );
    mQCertChain.append( qcert );
  }
  return true;
}

void QgsAuthCertInfo::setCertHeirarchy()
{
  QListIterator<QSslCertificate> it( mQCertChain );
  it.toBack();
  int i = mQCertChain.size();
  QTreeWidgetItem * item = 0;
  QTreeWidgetItem * previtem = 0;
  while (it.hasPrevious())
  {
    QSslCertificate cert( it.previous() );
    QString cert_source( QgsAuthCertUtils::resolvedCertName( cert ) );
    QString sha = QgsAuthCertUtils::shaHexForCert( cert );
    if ( mCaCertsCache.contains( sha ) )
    {
      const QPair<QgsAuthCertUtils::CaCertSource, QSslCertificate >& certpair( mCaCertsCache.value( sha ) );
      cert_source += QString( " (%1)").arg( QgsAuthCertUtils::getCaSourceName( certpair.first, true ) );
    }
    if ( !previtem )
    {
      item = new QTreeWidgetItem( treeHeirarchy, QStringList() << cert_source );
    }
    else
    {
      item = new QTreeWidgetItem( previtem, QStringList() << cert_source );
    }
    item->setData( 0, Qt::UserRole, --i );

    if ( mDefaultItemForeground.style() == Qt::NoBrush )
    {
      mDefaultItemForeground = item->foreground( 0 );
    }

    decorateCertTreeItem( cert, QgsAuthManager::instance()->getCertificateTrustPolicy( cert ), item );

    item->setFirstColumnSpanned( true );
    if ( !previtem )
      treeHeirarchy->addTopLevelItem( item );
    previtem = item;
  }
  treeHeirarchy->setCurrentItem( item, 0, QItemSelectionModel::ClearAndSelect );
}

void QgsAuthCertInfo::updateCurrentCertInfo( int chainindx )
{
  btnSaveTrust->setEnabled( false );

  mCurrentQCert = mQCertChain.at( chainindx );
  mCurrentACert = mACertChain.at( chainindx );

  QgsAuthCertUtils::CertTrustPolicy trustpolicy( QgsAuthManager::instance()->getCertificateTrustPolicy( mCurrentQCert ) );
  mCurrentTrustPolicy = trustpolicy;
  cmbbxTrust->setTrustPolicy( trustpolicy );
  if ( !mCurrentQCert.isValid() )
  {
    cmbbxTrust->setDefaultTrustPolicy( QgsAuthCertUtils::Untrusted );
  }

  populateCertDetails();
  populateCertPemText();
}

void QgsAuthCertInfo::populateCertDetails()
{
  //QgsAuthCertUtils::resolvedCertName( mCurrentQCert )

}

void QgsAuthCertInfo::populateCertPemText()
{
  ptePem->setPlainText( mCurrentQCert.toPem() );
}

void QgsAuthCertInfo::on_btnSaveTrust_clicked()
{
  QgsAuthCertUtils::CertTrustPolicy newpolicy( cmbbxTrust->trustPolicy() );
  if ( !QgsAuthManager::instance()->storeCertTrustPolicy( mCurrentQCert, newpolicy ) )
  {
    QgsDebugMsg( "Could not set trust policy for certificate" );
  }
  mCurrentTrustPolicy = newpolicy;
  decorateCertTreeItem( mCurrentQCert, newpolicy, 0 );
  btnSaveTrust->setEnabled( false );

  // rebuild trust cache
  QgsAuthManager::instance()->rebuildCertTrustCache();
  mTrustCacheRebuilt = true;
  QgsAuthManager::instance()->rebuildTrustedCaCertsCache();
}

void QgsAuthCertInfo::currentPolicyIndexChanged( int indx )
{
  QgsAuthCertUtils::CertTrustPolicy newpolicy( cmbbxTrust->trustPolicyForIndex( indx ) );
  btnSaveTrust->setEnabled( newpolicy != mCurrentTrustPolicy );
}

void QgsAuthCertInfo::decorateCertTreeItem( const QSslCertificate &cert,
                                            QgsAuthCertUtils::CertTrustPolicy trustpolicy,
                                            QTreeWidgetItem * item )
{
  if ( !item )
  {
    item = treeHeirarchy->currentItem();
  }
  if ( !item )
  {
    return;
  }

  if ( !cert.isValid() )
  {
    item->setIcon( 0, QgsApplication::getThemeIcon( "/mIconCertificateUntrusted.svg" ) );
    return;
  }

  if ( trustpolicy == QgsAuthCertUtils::Trusted )
  {
    item->setIcon( 0, QgsApplication::getThemeIcon( "/mIconCertificateTrusted.svg" ) );
  }
  else if ( trustpolicy == QgsAuthCertUtils::Untrusted
            || ( trustpolicy == QgsAuthCertUtils::DefaultTrust
                 && mDefaultTrustPolicy == QgsAuthCertUtils::Untrusted ) )
  {
    item->setIcon( 0, QgsApplication::getThemeIcon( "/mIconCertificateUntrusted.svg" ) );
  }
  else
  {
    item->setIcon( 0, QgsApplication::getThemeIcon( "/mIconCertificate.svg" ) );
  }
}
