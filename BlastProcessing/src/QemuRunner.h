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

    void runQemu();

protected slots:

    void preProcessError(QProcess::ProcessError err);

    void preProcessComplete(int exitCode);

    void periProcessError(QProcess::ProcessError err);

    void periProcessComplete(int exitCode, QProcess::ExitStatus exitStatus);

    void postProcessError(QProcess::ProcessError err);

    void postProcessComplete(int exitCode, QProcess::ExitStatus exitStatus);

protected:

    int theInstanceId;

    QemuConfiguration theCfg;

    QString thePreScript;
    QString thePeriScript;
    QString thePostScript;

    QProcess* thePreProcess;
    QProcess* thePeriProcess;
    QProcess* thePostProcess;

    QTimer* thePreProcessTimer;
    QTimer* thePeriProcessTimer;
    QTimer* thePostProcessTimer;
    QTimer* theProgressUpdateTimer;

    int theTimeout;

    bool theRunFlag;

    bool thePreInProgressFlag;

};

#endif // QEMURUNNER_H
