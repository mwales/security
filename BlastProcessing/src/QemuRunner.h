#ifndef QEMURUNNER_H
#define QEMURUNNER_H

#include <QObject>
#include <QProcess>
#include <QTimer>
#include "QemuConfiguration.h"


class QemuRunner : public QObject
{
Q_OBJECT

public:
    QemuRunner(int id, QemuConfiguration const & cfg);

    void setScripts(QString pre, QString peri, QString post);

    void setTimeout(int secs);

    void stopTests();

    int getInstanceId() { return theInstanceId; }

signals:

    void runnerStarted();

    void runnerStopped(QemuRunner* whichRunner);

    void testStarted(int testId);

    void testProgress(int stage, int seconds);

    void testComplete(QString result);

public slots:

    void runnerThreadStart();

protected slots:

    void runnerProcessError(QProcess::ProcessError err);

    void runnerProcessComplete(int exitCode);

    void tickUpdate();

protected:

    void startNextState();

    void startScript(QString scriptCommand);

    void resetTimers();

    void seeding();

    void saveResults();


    enum class RunnerState
    {
        NOT_RUNNING,
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

    bool theRunFlag;


};

#endif // QEMURUNNER_H
