#ifndef BLASTPROCESSING_H
#define BLASTPROCESSING_H

#include <QDialog>
#include <QSignalMapper>
#include <set>
#include "QemuConfiguration.h"

namespace Ui {
class BlastProcessing;
}

class QemuRunner;

class BlastProcessing : public QDialog
{
    Q_OBJECT

public:
    explicit BlastProcessing(QemuConfiguration const & cfg, QWidget *parent = 0);
    ~BlastProcessing();

protected slots:

    void runnerStopped(QemuRunner* stoppedRunner);

protected:

    void startButtonPressed();

    void stopButtonPressed();

    void  closeEvent(QCloseEvent * ev);

private:

    void stopThreadsAndWait();

    Ui::BlastProcessing *ui;

    QemuConfiguration theCfg;

    std::map<QemuRunner*, QThread*> theRunners;

    QSignalMapper theSignalMapper;
};

#endif // BLASTPROCESSING_H
