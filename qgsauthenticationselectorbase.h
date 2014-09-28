#ifndef QGSAUTHENTICATIONSELECTORBASE_H
#define QGSAUTHENTICATIONSELECTORBASE_H

#include <QWidget>

namespace Ui {
class QgsAuthenticationSelectorBase;
}

class QgsAuthenticationSelectorBase : public QWidget
{
    Q_OBJECT

  public:
    explicit QgsAuthenticationSelectorBase(QWidget *parent = 0);
    ~QgsAuthenticationSelectorBase();

  private:
    Ui::QgsAuthenticationSelectorBase *ui;
};

#endif // QGSAUTHENTICATIONSELECTORBASE_H
