/***************************************************************************
    qgsauthenticationsslconfigwidget.cpp
    ---------------------
    begin                : May 17, 2015
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

#include "qgsauthenticationsslconfigwidget.h"
#include "qgsauthenticationcertificateinfo.h"

#include <QDialogButtonBox>
#include <QPushButton>
#include <QSpinBox>

#include "qgsauthenticationmanager.h"
#include "qgslogger.h"


static void setItemBold_( QTreeWidgetItem* item )
{
  item->setFirstColumnSpanned( true );
  QFont secf( item->font( 0 ) );
  secf.setBold( true );
  item->setFont( 0, secf );
}

static const QString configFoundText_() { return QObject::tr( "Configuration loaded from database" ); }
static const QString configNotFoundText_() { return QObject::tr( "Configuration not found in database" ); }

QgsAuthSslConfigWidget::QgsAuthSslConfigWidget( QWidget *parent,
                                                const QSslCertificate& cert,
                                                const QList<QSslCertificate> &connectionCAs )
  : QWidget( parent )
  , mCert( 0 )
  , mConnectionCAs( connectionCAs )
  , mProtocolItem( 0 )
  , mProtocolCmbBx( 0 )
  , mIgnoreErrorsItem( 0 )
  , mVerifyModeItem( 0 )
  , mVerifyPeerCmbBx( 0 )
  , mVerifyDepthItem( 0 )
  , mVerifyDepthSpnBx( 0 )
{
  setupUi( this );

  connect( grpbxSslConfig, SIGNAL( toggled(bool) ), this, SIGNAL( configEnabled( bool ) ) );

  setUpSslConfigTree();

  lblLoadedConfig->setShown( false );
  lblLoadedConfig->setText( "" );

  if ( !cert.isNull() )
  {
    setSslCertificate( cert );
  }
}

QgsAuthSslConfigWidget::~QgsAuthSslConfigWidget()
{
}

// private
QTreeWidgetItem* QgsAuthSslConfigWidget::addRootItem( const QString &label )
{
  QTreeWidgetItem *item = new QTreeWidgetItem(
        QStringList() << label,
        ( int )ConfigParent );
  setItemBold_( item );
  item->setTextAlignment( 0, Qt::AlignVCenter );
  item->setFlags( item->flags() & ~Qt::ItemIsSelectable );
  treeSslConfig->insertTopLevelItem( treeSslConfig->topLevelItemCount(), item);

  return item;
}

void QgsAuthSslConfigWidget::setUpSslConfigTree()
{
  treeSslConfig->setColumnCount( 1 );

  // add config field names
  mProtocolItem = addRootItem( tr( "Protocol" ) );
  mProtocolCmbBx = new QComboBox( treeSslConfig );
#if QT_VERSION >= 0x040800
  mProtocolCmbBx->addItem( QgsAuthCertUtils::getSslProtocolName( QSsl::SecureProtocols ),
                           ( int )QSsl::SecureProtocols );
  mProtocolCmbBx->addItem( QgsAuthCertUtils::getSslProtocolName( QSsl::TlsV1SslV3 ),
                           ( int )QSsl::TlsV1SslV3 );
#endif
  mProtocolCmbBx->addItem( QgsAuthCertUtils::getSslProtocolName( QSsl::TlsV1 ),
                           ( int )QSsl::TlsV1 );
  mProtocolCmbBx->addItem( QgsAuthCertUtils::getSslProtocolName( QSsl::SslV3 ),
                           ( int )QSsl::SslV3 );
  mProtocolCmbBx->addItem( QgsAuthCertUtils::getSslProtocolName( QSsl::SslV2 ),
                           ( int )QSsl::SslV2 );
  mProtocolCmbBx->setMaximumWidth( 300 );
  mProtocolCmbBx->setCurrentIndex( 0 );
  QTreeWidgetItem *protocolitem = new QTreeWidgetItem(
        mProtocolItem,
        QStringList() << "",
        ( int )ConfigItem );
  protocolitem->setFlags( protocolitem->flags() & ~Qt::ItemIsSelectable );
  treeSslConfig->setItemWidget( protocolitem, 0, mProtocolCmbBx );
  mProtocolItem->setExpanded( true );

  mVerifyModeItem = addRootItem( tr( "Peer verification" ) );
  mVerifyPeerCmbBx = new QComboBox( treeSslConfig );
  mVerifyPeerCmbBx->addItem( tr( "Verify peer certs" ),
                           ( int )QSslSocket::VerifyPeer );
  mVerifyPeerCmbBx->addItem( tr( "Do not verify peer certs" ),
                           ( int )QSslSocket::VerifyNone );
  mVerifyPeerCmbBx->setMaximumWidth( 300 );
  mVerifyPeerCmbBx->setCurrentIndex( 0 );
  QTreeWidgetItem *peerverifycmbxitem = new QTreeWidgetItem(
        mVerifyModeItem,
        QStringList() << "",
        ( int )ConfigItem );
  peerverifycmbxitem->setFlags( peerverifycmbxitem->flags() & ~Qt::ItemIsSelectable );
  treeSslConfig->setItemWidget( peerverifycmbxitem, 0, mVerifyPeerCmbBx );
  mVerifyModeItem->setExpanded( true );

  mVerifyDepthItem = addRootItem( tr( "Peer verification depth (0 = complete cert chain)" ) );
  mVerifyDepthSpnBx = new QSpinBox( treeSslConfig );
  mVerifyDepthSpnBx->setMinimum( 0 );
  mVerifyDepthSpnBx->setMaximum( 10 );
  mVerifyDepthSpnBx->setMaximumWidth( 200 );
  mVerifyDepthSpnBx->setAlignment( Qt::AlignHCenter );
  QTreeWidgetItem *peerverifyspnbxitem = new QTreeWidgetItem(
        mVerifyDepthItem,
        QStringList() << "",
        ( int )ConfigItem );
  peerverifyspnbxitem->setFlags( peerverifyspnbxitem->flags() & ~Qt::ItemIsSelectable );
  treeSslConfig->setItemWidget( peerverifyspnbxitem, 0, mVerifyDepthSpnBx );
  mVerifyDepthItem->setExpanded( true );

  mIgnoreErrorsItem = addRootItem( tr( "Ignore errors" ) );

  QList<QPair<QSslError::SslError, QString> > errenums = QgsAuthCertUtils::sslErrorEnumStrings();
  for ( int i = 0; i < errenums.size(); i++ )
  {
    QTreeWidgetItem *item = new QTreeWidgetItem(
          mIgnoreErrorsItem,
          QStringList() << errenums.at( i ).second,
          ( int )ConfigItem );
    item->setCheckState( 0, Qt::Unchecked );
    item->setTextAlignment( 0, Qt::AlignVCenter );
    item->setFlags( item->flags() & ~Qt::ItemIsSelectable );
    item->setData( 0, Qt::UserRole, errenums.at( i ).first );
  }
  mIgnoreErrorsItem->setExpanded( true );
}

const QgsAuthConfigSslServer QgsAuthSslConfigWidget::sslCustomConfig()
{
  QgsAuthConfigSslServer config;
  config.setSslCertificate( mCert );
  config.setSslHost( leHost->text() );
  config.setSslProtocol( sslProtocol() );
  config.setSslIgnoredErrorEnums( sslIgnoreErrors() );
  config.setSslPeerVerify( sslPeerVerify() );
  return config;
}

void QgsAuthSslConfigWidget::enableSslCustomOptions( bool enable )
{
  grpbxSslConfig->setChecked( enable );
}

void QgsAuthSslConfigWidget::setSslCertificate( const QSslCertificate &cert )
{
  if ( cert.isNull() )
  {
    return;
  }
  mCert = cert;

  QString sha( QgsAuthCertUtils::shaHexForCert( cert ) );
  QgsAuthConfigSslServer config( QgsAuthManager::instance()->getSslCertCustomConfig( sha ) );

  emit certFoundInAuthDatabase( !config.isNull() );

  lblLoadedConfig->setShown( true );
  if ( !config.isNull() )
  {
    loadSslCustomConfig( config );
    leCommonName->setStyleSheet( QgsAuthCertUtils::greenTextStyleSheet() );
  }
  else
  {
    lblLoadedConfig->setText( configNotFoundText_() );
    leCommonName->setText( QgsAuthCertUtils::resolvedCertName( mCert ) );
    leCommonName->setStyleSheet( QgsAuthCertUtils::orangeTextStyleSheet() );
  }
}

void QgsAuthSslConfigWidget::loadSslCustomConfig( const QgsAuthConfigSslServer &config )
{
  resetSslCertConfig();
  if ( config.isNull() )
  {
    QgsDebugMsg( "Passed-in SSL custom config is null" );
    return;
  }

  QSslCertificate cert( config.sslCertificate() );
  if ( cert.isNull() )
  {
    QgsDebugMsg( "SSL custom config's cert is null" );
    return;
  }

  enableSslCustomOptions( true );
  mCert = cert;
  leCommonName->setText( QgsAuthCertUtils::resolvedCertName( cert ) );
  leHost->setText( config.sslHost() );
  setSslIgnoreErrorEnums( config.sslIgnoredErrorEnums() );
  setSslProtocol( config.sslProtocol() );
  setSslPeerVerify( config.sslPeerVerify() );

  lblLoadedConfig->setShown( true );
  lblLoadedConfig->setText( configFoundText_() );
}

void QgsAuthSslConfigWidget::saveSslCertConfig()
{
  if ( !QgsAuthManager::instance()->storeSslCertCustomConfig( sslCustomConfig() ) )
  {
    QgsDebugMsg( "SSL custom config FAILED to store in authentication database" );
  }
}

void QgsAuthSslConfigWidget::resetSslCertConfig()
{
  mCert.clear();
  mConnectionCAs.clear();
  leCommonName->clear();
  leCommonName->setStyleSheet( "" );
  leHost->clear();

  lblLoadedConfig->setShown( false );
  lblLoadedConfig->setText( "" );
  resetSslProtocol();
  resetSslIgnoreErrors();
  resetSslPeerVerify();
  enableSslCustomOptions( false );
}

QSsl::SslProtocol QgsAuthSslConfigWidget::sslProtocol()
{
  return ( QSsl::SslProtocol )mProtocolCmbBx->itemData( mProtocolCmbBx->currentIndex() ).toInt();
}

void QgsAuthSslConfigWidget::setSslProtocol( QSsl::SslProtocol protocol )
{
  int indx( mProtocolCmbBx->findData(( int )protocol ) );
  mProtocolCmbBx->setCurrentIndex( indx );
}

void QgsAuthSslConfigWidget::resetSslProtocol()
{
  mProtocolCmbBx->setCurrentIndex( 0 );
}

void QgsAuthSslConfigWidget::appendSslIgnoreErrors( const QList<QSslError> &errors )
{
  enableSslCustomOptions( true );

  QList<QSslError::SslError> errenums;
  Q_FOREACH( const QSslError& err, errors )
  {
    errenums << err.error();
  }

  for ( int i = 0; i < mIgnoreErrorsItem->childCount(); i++ )
  {
    QTreeWidgetItem *item( mIgnoreErrorsItem->child( i ) );
    if ( errenums.contains(( QSslError::SslError )item->data( 0, Qt::UserRole ).toInt() ) )
    {
      item->setCheckState( 0, Qt::Checked );
    }
  }
}

void QgsAuthSslConfigWidget::setSslIgnoreErrorEnums( const QList<QSslError::SslError> &errorenums )
{
  QList<QSslError> errors;
  Q_FOREACH ( QSslError::SslError errorenum, errorenums )
  {
    errors << QSslError( errorenum );
  }
  setSslIgnoreErrors( errors );
}

void QgsAuthSslConfigWidget::setSslIgnoreErrors( const QList<QSslError> &errors )
{
  if ( errors.isEmpty() )
  {
    return;
  }

  enableSslCustomOptions( true );

  QList<QSslError::SslError> errenums;
  Q_FOREACH( const QSslError& err, errors )
  {
    errenums << err.error();
  }

  for ( int i = 0; i < mIgnoreErrorsItem->childCount(); i++ )
  {
    QTreeWidgetItem *item( mIgnoreErrorsItem->child( i ) );
    bool enable( errenums.contains(( QSslError::SslError )item->data( 0, Qt::UserRole ).toInt() ) );
    item->setCheckState( 0, enable ? Qt::Checked : Qt::Unchecked );
  }
}

void QgsAuthSslConfigWidget::resetSslIgnoreErrors()
{
  for ( int i = 0; i < mIgnoreErrorsItem->childCount(); i++ )
  {
    mIgnoreErrorsItem->child( i )->setCheckState( 0, Qt::Unchecked );
  }
}

const QList<QSslError::SslError> QgsAuthSslConfigWidget::sslIgnoreErrors()
{
  QList<QSslError::SslError> errs;
  for ( int i = 0; i < mIgnoreErrorsItem->childCount(); i++ )
  {
    QTreeWidgetItem *item( mIgnoreErrorsItem->child( i ) );
    if ( item->checkState( 0 ) == Qt::Checked )
    {
      errs.append(( QSslError::SslError )item->data( 0, Qt::UserRole ).toInt() );
    }
  }
  return errs;
}

const QPair<QSslSocket::PeerVerifyMode, int> QgsAuthSslConfigWidget::sslPeerVerify()
{
  return qMakePair(( QSslSocket::PeerVerifyMode )mVerifyPeerCmbBx->itemData( mVerifyPeerCmbBx->currentIndex() ).toInt(),
                   mVerifyDepthSpnBx->value() );
}


void QgsAuthSslConfigWidget::setSslPeerVerify( const QPair<QSslSocket::PeerVerifyMode, int> &modedepth )
{
  enableSslCustomOptions( true );

  int indx( mVerifyPeerCmbBx->findData(( int )modedepth.first ) );
  mVerifyPeerCmbBx->setCurrentIndex( indx );

  mVerifyDepthSpnBx->setValue( modedepth.second );
}

void QgsAuthSslConfigWidget::resetSslPeerVerify()
{
  mVerifyPeerCmbBx->setCurrentIndex( 0 );
  mVerifyDepthSpnBx->setValue( 0 );
}

void QgsAuthSslConfigWidget::setSslHost( const QString &host )
{
  leHost->setText( host );
}

void QgsAuthSslConfigWidget::setConfigCheckable( bool checkable )
{
  grpbxSslConfig->setCheckable( checkable );
}

void QgsAuthSslConfigWidget::on_btnCertInfo_clicked()
{
  if ( mCert.isNull() )
  {
    return;
  }

  QgsAuthCertInfoDialog * dlg = new QgsAuthCertInfoDialog( mCert, false, this, mConnectionCAs );
  dlg->setWindowModality( Qt::WindowModal );
  dlg->resize( 675, 500 );
  dlg->exec();
  dlg->deleteLater();
}


//////////////// Embed in dialog ///////////////////

QgsAuthSslConfigDialog::QgsAuthSslConfigDialog( QWidget *parent , const QSslCertificate& cert )
  : QDialog( parent )
  , mSslConfigWdgt( 0 )
{
  setWindowTitle( tr( "Custom Certificate Configuration" ) );
  QVBoxLayout *layout = new QVBoxLayout( this );
  layout->setMargin( 6 );

  mSslConfigWdgt = new QgsAuthSslConfigWidget( this, cert );
  layout->addWidget( mSslConfigWdgt );

  QDialogButtonBox *buttonBox = new QDialogButtonBox(
        QDialogButtonBox::Close | QDialogButtonBox::Save, Qt::Horizontal, this );

  buttonBox->button( QDialogButtonBox::Close )->setDefault( true );
  connect( buttonBox, SIGNAL( rejected() ), this, SLOT( close() ) );
  connect( buttonBox, SIGNAL( accepted() ), this, SLOT( accept() ) );
  layout->addWidget( buttonBox );

  setLayout( layout );
}

QgsAuthSslConfigDialog::~QgsAuthSslConfigDialog()
{
}

void QgsAuthSslConfigDialog::accept()
{
  mSslConfigWdgt->saveSslCertConfig();
  QDialog::accept();
}
