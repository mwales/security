#ifndef QEMURUNNER_H
#define QEMURUNNER_H

#include <QObject>
#include <QProcess>
#include <QTimer>
#include "QemuConfiguration.h"

class QemuProcessManager;


class QemuRunner : public QObject
{
Q_OBJECT

public:
    QemuRunner(int id, QemuConfiguration const & cfg);

    void setScripts(QString pre, QString peri, QString post);

    void setTimeout(int secs);

    void stopTests();

    int getInstanceId() { return theInstanceId; }

    void useQemuEmulator(bool enable,
                         QString snapshotName,
                         bool sendKeystrokes,
                         QString keystrokes);

signals:

    void runnerStarted();

    void runnerStopped(QObject* whichRunner);

    void testStarted(int testId);

    void testProgress(int zeroTo300);

    void testComplete(QString result);

public slots:

    void runnerThreadStart();

protected slots:

    void runnerProcessError(QProcess::ProcessError err);

    void runnerProcessComplete(int exitCode);

    void tickUpdate();

    void qemuStarted();

    void qemuStopped();

protected:

    void startNextState();

    void startScript(QString scriptCommand);

    void resetTimers();

    void seeding();

    void saveResults();

    void startQemu();

    void stopQemu();

    void executePeriState();


    enum class RunnerState
    {
        NOT_RUNNING,
        STARTING_QEMU,
        PRE_RUNNING,
        PERI_RUNNING,
        POST_RUNNING,
        SAVE_RESULTS
    };

    enum RunnerState theState;

    int theInstanceId;
    int theTestId;

    QemuConfiguration theCfg;

    QString thePreScript;
    QString thePeriScript;
    QString thePostScript;

    QProcess* theRunningProcess;

    QTimer* theProgressUpdateTimer;

    int theTimeout;
    int theCurrentProcTime;
    int theProgressPerTick;

    bool theRunFlag;
    bool theBadErrorFlag;

    bool theUseQemuFlag;
    QemuProcessManager* theQemuProcess;

    QString theQemuSnapshotName;

    bool theSendQemuKeystrokesFlag;
    QString theQemuKeystrokes;
};

#endif // QEMURUNNER_H
