// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2022-2026 sbrown7792 and MultiPCAPSearch contributors

#ifndef LIVEMONITOR_H
#define LIVEMONITOR_H

#include <QHash>
#include <QObject>
#include <QSet>
#include <QString>
#include <QStringList>

#include <functional>

#include "capturefollower.h"

class QProcess;

// Keeps live packet counts for every (capture file, filter) pair by running
// CaptureFollowers, so counts grow as the captures do.
//
// With tshark 4.4 or newer, one follower per file evaluates all filters at once.
// Older tshark can only apply one filter per process, so there is one follower
// per (file, filter) pair instead: same results, more memory.
//
// Each filter is first checked on its own, so one bad filter only affects its
// own column rather than stopping a shared follower.
class LiveMonitor : public QObject
{
    Q_OBJECT

public:
    enum class Capability { Unknown, Probing, MultiFilter, SingleFilter };

    struct CellState
    {
        enum Status { Starting, Following, Error };
        Status status = Starting;
        qint64 count = 0;
        bool caughtUp = false;
        QString message;
    };

    explicit LiveMonitor(QObject *parent = nullptr);
    ~LiveMonitor() override;

    void setTsharkPath(const QString &path);

    // Starts or stops following. Stopping ends all tshark processes.
    void setActive(bool active);
    bool isActive() const { return m_active; }

    // The captures and filters to follow. Duplicates are ignored.
    void setTargets(const QStringList &files, const QStringList &filters);

    CellState state(const QString &file, const QString &filter) const;

    Capability capability() const { return m_capability; }
    int processCount() const { return m_followers.size(); }

    // Always use one tshark per (file, filter), even if tshark could do better.
    void setForceSingleFilter(bool force);

    // For tests: how often followers look for new data.
    void setPollInterval(int ms) { m_pollInterval = ms; }

signals:
    void changed();

private:
    void sync();
    void probeCapability();
    void validate(const QString &filter);
    void runProbe(const QStringList &args, std::function<void(bool ok, const QString &message)> done);
    void clearFollowers();
    QString followerKey(const QString &file, const QString &filter) const;
    bool multiFilter() const;

    QString m_tshark;
    bool m_active = false;
    bool m_forceSingle = false;
    int m_pollInterval = 500;
    QStringList m_files;
    QStringList m_filters;

    Capability m_capability = Capability::Unknown;
    QHash<QString, QString> m_filterErrors;     // checked filters -> error message ("" if valid)
    QSet<QString> m_validating;
    int m_generation = 0;                        // bumped when tshark changes, to drop stale probes

    QHash<QString, CaptureFollower *> m_followers;
};

#endif // LIVEMONITOR_H
