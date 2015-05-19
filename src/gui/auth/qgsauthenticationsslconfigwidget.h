/***************************************************************************
    qgsauthenticationsslconfigwidget.h
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

#ifndef QGSAUTHENTICATIONSSLCONFIGWIDGET_H
#define QGSAUTHENTICATIONSSLCONFIGWIDGET_H

#include <QDialog>
#include <QWidget>
#include "ui_qgsauthenticationsslconfigwidget.h"

#include <QSslCertificate>
#include <QSslConfiguration>

#include "qgsauthenticationconfig.h"

class QComboBox;
class QSpinBox;

class GUI_EXPORT QgsAuthSslConfigWidget : public QWidget, private Ui::QgsAuthSslConfigWidget
{
    Q_OBJECT

  public:
    enum ConfigType
    {
      ConfigParent = 1000,
      ConfigItem = 1001,
    };

    explicit QgsAuthSslConfigWidget( QWidget *parent = 0,
                                     const QSslCertificate &cert = QSslCertificate(),
                                     const QList<QSslCertificate>& connectionCAs = QList<QSslCertificate>() );
    ~QgsAuthSslConfigWidget();

    const QgsAuthConfigSslServer sslCustomConfig();

    const QSslCertificate sslCertificate() { return mCert; }

    const QString sslHost() { return leHost->text(); }

    QSsl::SslProtocol sslProtocol();

    const QList<QSslError> sslIgnoreErrors();

    const QPair<QSslSocket::PeerVerifyMode, int> sslPeerVerify();

  public slots:
    void enableSslCustomOptions( bool enable );

    // may also load existing config, if found
    void setSslCertificate( const QSslCertificate& cert );

    void loadSslCustomConfig( const QgsAuthConfigSslServer& config = QgsAuthConfigSslServer() );

    void saveSslCertConfig();

    void resetSslCertConfig();

    void setSslProtocol( QSsl::SslProtocol protocol );

    void resetSslProtocol();

    void appendSslIgnoreErrors( const QList<QSslError>& errors );

    void setSslIgnoreErrors( const QList<QSslError>& errors );

    void resetSslIgnoreErrors();

    void setSslPeerVerify( const QPair<QSslSocket::PeerVerifyMode, int>& modedepth );

    void resetSslPeerVerify();

    void setSslHost( const QString& host );

    void setConfigCheckable( bool checkable );

  signals:
    void configEnabled( bool enabled );
    void certFoundInAuthDatabase( bool found );

  private slots:
    void on_btnCertInfo_clicked();

  private:
    void setUpSslConfigTree();
    QTreeWidgetItem* addRootItem( const QString& label );

    QSslCertificate mCert;
    QList<QSslCertificate> mConnectionCAs;

    QTreeWidgetItem *mRootItem;
    QTreeWidgetItem *mProtocolItem;
    QComboBox *mProtocolCmbBx;
    QTreeWidgetItem *mIgnoreErrorsItem;
    QTreeWidgetItem *mVerifyModeItem;
    QComboBox *mVerifyPeerCmbBx;
    QTreeWidgetItem *mVerifyDepthItem;
    QSpinBox *mVerifyDepthSpnBx;
};

//////////////// Embed in dialog ///////////////////

class GUI_EXPORT QgsAuthSslConfigDialog : public QDialog
{
    Q_OBJECT

  public:
    explicit QgsAuthSslConfigDialog( QWidget *parent = 0,
                                     const QSslCertificate& cert = QSslCertificate() );
    ~QgsAuthSslConfigDialog();

    QgsAuthSslConfigWidget *sslCustomConfigWidget() { return mSslConfigWdgt; }

  public slots:
      void accept();

  private:
    QgsAuthSslConfigWidget *mSslConfigWdgt;
};

#endif // QGSAUTHENTICATIONSSLCONFIGWIDGET_H
