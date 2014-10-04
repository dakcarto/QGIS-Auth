#ifndef QGSAUTHENTICATIONSELECTORBASE_H
#define QGSAUTHENTICATIONSELECTORBASE_H

#include <QWidget>

namespace Ui
{
  class QgsAuthSelectorBase;
}

class QgsAuthSelectorBase : public QWidget
{
    Q_OBJECT

  public:
    explicit QgsAuthSelectorBase( QWidget *parent = 0 );
    ~QgsAuthSelectorBase();

  private:
    Ui::QgsAuthSelectorBase *ui;
};

#endif // QGSAUTHENTICATIONSELECTORBASE_H
