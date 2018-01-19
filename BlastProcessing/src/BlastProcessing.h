#ifndef BLASTPROCESSING_H
#define BLASTPROCESSING_H

#include <QMainWindow>
#include <QSignalMapper>
#include <utility>
#include <vector>
#include "QemuConfiguration.h"

namespace Ui {
class MainWindow;
}

class BlastProcessing : public QMainWindow
{
    Q_OBJECT

public:
    explicit BlastProcessing(QemuConfiguration const & cfg,
                             QString configFile,
                             QWidget *parent = 0);
    ~BlastProcessing();

protected slots:

    void runnerStopped(QObject* stoppedRunner);

    void setNumInstancesUpdated(int numProcesses);

    void saveGuiConfigFile(QString filename);

    void loadGuiConfigFile(QString filename);

    void saveButtonPressed();

    void loadButtonPressed();

    void invalidateConfig();

protected:

    void startButtonPressed();

    void stopButtonPressed();

    void  closeEvent(QCloseEvent * ev);

private:

    void stopThreadsAndWait();

    void spawnRunner(int instanceId);

    void createProgressControls();

    Ui::BlastProcessing *ui;

    QemuConfiguration theCfg;
    bool theStoredConfigValid;

    std::map< int, std::pair<BPRunner*, QThread*> > theRunners;

    QSignalMapper theSignalMapper;

    int theNumInstancesToRun;

    //*******
    // Runner status stuff
    //*******

    QVBoxLayout* theStatusLayout;

    struct ProgressControls
    {
        QLabel* theId;
        QProgressBar* theProgress;
        QLineEdit* theEdit;
        QHBoxLayout* theLayout;
    };

    void setNumRunnerProgressToShow(int count);


    QLabel* theMoreNotShownLabel;

    std::vector<struct ProgressControls> theRunnerStatusUi;


};

#endif // BLASTPROCESSING_H
