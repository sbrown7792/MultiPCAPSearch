// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2022-2026 sbrown7792 and MultiPCAPSearch contributors

#include "livemonitor.h"

#include <QProcess>

namespace
{
    // A capture with no packets: a classic pcap header, Ethernet link type.
    QByteArray emptyPcap()
    {
        static const unsigned char header[24] = {
            0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
            0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
        return QByteArray(reinterpret_cast<const char *>(header), sizeof(header));
    }

    QStringList unique(const QStringList &items)
    {
        QStringList out;
        for (const QString &item : items)
        {
            if (!out.contains(item))
                out << item;
        }
        return out;
    }
}

LiveMonitor::LiveMonitor(QObject *parent)
    : QObject(parent)
{
}

LiveMonitor::~LiveMonitor()
{
    clearFollowers();
    for (QProcess *probe : findChildren<QProcess *>(Qt::FindDirectChildrenOnly))
    {
        probe->disconnect();
        probe->kill();
        probe->waitForFinished(1000);
    }
}

void LiveMonitor::setTsharkPath(const QString &path)
{
    if (path == m_tshark)
        return;
    m_tshark = path;
    ++m_generation;
    m_capability = Capability::Unknown;
    m_filterErrors.clear();
    m_validating.clear();
    clearFollowers();
    sync();
}

void LiveMonitor::setActive(bool active)
{
    if (active == m_active)
        return;
    m_active = active;
    sync();
}

void LiveMonitor::setTargets(const QStringList &files, const QStringList &filters)
{
    QStringList trimmed;
    for (const QString &filter : filters)
        trimmed << filter.trimmed();

    const QStringList newFiles = unique(files);
    const QStringList newFilters = unique(trimmed);
    if (newFiles == m_files && newFilters == m_filters)
        return;
    m_files = newFiles;
    m_filters = newFilters;
    sync();
}

void LiveMonitor::setForceSingleFilter(bool force)
{
    if (force == m_forceSingle)
        return;
    m_forceSingle = force;
    clearFollowers();
    sync();
}

bool LiveMonitor::multiFilter() const
{
    return m_capability == Capability::MultiFilter && !m_forceSingle;
}

QString LiveMonitor::followerKey(const QString &file, const QString &filter) const
{
    return multiFilter() ? file : file + QChar(0) + filter;
}

void LiveMonitor::clearFollowers()
{
    for (CaptureFollower *follower : std::as_const(m_followers))
    {
        follower->disconnect(this);
        follower->deleteLater();
    }
    m_followers.clear();
}

LiveMonitor::CellState LiveMonitor::state(const QString &file, const QString &filterText) const
{
    const QString filter = filterText.trimmed();
    CellState state;

    if (m_tshark.isEmpty())
    {
        state.status = CellState::Error;
        state.message = tr("tshark was not found. Install Wireshark, or use Settings > Locate tshark...");
        return state;
    }

    const auto error = m_filterErrors.constFind(filter);
    if (error != m_filterErrors.cend() && !error->isEmpty())
    {
        state.status = CellState::Error;
        state.message = *error;
        return state;
    }

    const CaptureFollower *follower = m_followers.value(followerKey(file, filter));
    const int index = follower ? follower->filters().indexOf(filter) : -1;
    if (index < 0)
        return state;   // still starting up (probing tshark or checking the filter)

    if (!follower->error().isEmpty())
    {
        state.status = CellState::Error;
        state.message = follower->error();
        return state;
    }

    state.status = CellState::Following;
    state.count = follower->counts().value(index);
    state.caughtUp = follower->caughtUp();
    return state;
}

void LiveMonitor::sync()
{
    if (!m_active || m_tshark.isEmpty())
    {
        clearFollowers();
        emit changed();
        return;
    }

    if (m_capability == Capability::Unknown)
        probeCapability();
    if (m_capability == Capability::Probing)
    {
        emit changed();
        return;
    }

    // Check new filters one by one before handing them to a shared follower.
    for (const QString &filter : std::as_const(m_filters))
    {
        if (!filter.isEmpty() && !m_filterErrors.contains(filter))
            validate(filter);
    }
    if (!m_validating.isEmpty())
    {
        // Wait for all checks so shared followers don't restart (and re-read
        // the whole capture) once per filter.
        emit changed();
        return;
    }

    QStringList validFilters;
    for (const QString &filter : std::as_const(m_filters))
    {
        if (filter.isEmpty() || m_filterErrors.value(filter, QStringLiteral("?")).isEmpty())
            validFilters << filter;
    }

    // Work out which followers should exist, keyed like followerKey().
    QHash<QString, QPair<QString, QStringList>> wanted;
    for (const QString &file : std::as_const(m_files))
    {
        if (multiFilter())
        {
            if (!validFilters.isEmpty())
                wanted.insert(file, {file, validFilters});
        }
        else
        {
            for (const QString &filter : std::as_const(validFilters))
                wanted.insert(followerKey(file, filter), {file, {filter}});
        }
    }

    for (auto it = m_followers.begin(); it != m_followers.end();)
    {
        const auto want = wanted.constFind(it.key());
        if (want == wanted.cend() || want->second != it.value()->filters())
        {
            it.value()->disconnect(this);
            it.value()->deleteLater();
            it = m_followers.erase(it);
        }
        else
        {
            ++it;
        }
    }

    const auto mode = multiFilter() ? CaptureFollower::Mode::MultiFilter : CaptureFollower::Mode::SingleFilter;
    for (auto it = wanted.cbegin(); it != wanted.cend(); ++it)
    {
        if (m_followers.contains(it.key()))
            continue;
        auto *follower = new CaptureFollower(m_tshark, it->first, it->second, mode, this);
        follower->setPollInterval(m_pollInterval);
        connect(follower, &CaptureFollower::changed, this, &LiveMonitor::changed);
        m_followers.insert(it.key(), follower);
        follower->start();
    }

    emit changed();
}

void LiveMonitor::runProbe(const QStringList &args, std::function<void(bool, const QString &)> done)
{
    auto *probe = new QProcess(this);
    const int generation = m_generation;
    auto finish = [this, probe, generation, done](bool ok, const QString &message) {
        probe->disconnect(this);
        probe->deleteLater();
        if (generation == m_generation)
            done(ok, message);
    };

    connect(probe, &QProcess::finished, this, [probe, finish](int exitCode, QProcess::ExitStatus status) {
        const QString stdErr = QString::fromLocal8Bit(probe->readAllStandardError()).trimmed();
        finish(status == QProcess::NormalExit && exitCode == 0, stdErr);
    });
    connect(probe, &QProcess::errorOccurred, this, [probe, finish](QProcess::ProcessError error) {
        if (error == QProcess::FailedToStart)
            finish(false, probe->errorString());
    });
    connect(probe, &QProcess::started, probe, [probe]() {
        probe->write(emptyPcap());
        probe->closeWriteChannel();
    });

    probe->start(m_tshark, args);
}

void LiveMonitor::probeCapability()
{
    m_capability = Capability::Probing;
    // tshark 4.4 added display-filter expressions as -e fields; older versions reject this.
    runProbe({QStringLiteral("-n"), QStringLiteral("-r"), QStringLiteral("-"), QStringLiteral("-T"),
              QStringLiteral("fields"), QStringLiteral("-e"), CaptureFollower::expressionFor(QString())},
             [this](bool ok, const QString &) {
                 m_capability = ok ? Capability::MultiFilter : Capability::SingleFilter;
                 sync();
             });
}

void LiveMonitor::validate(const QString &filter)
{
    if (m_validating.contains(filter))
        return;
    m_validating.insert(filter);

    runProbe({QStringLiteral("-n"), QStringLiteral("-r"), QStringLiteral("-"), QStringLiteral("-Y"), filter},
             [this, filter](bool ok, const QString &message) {
                 m_validating.remove(filter);
                 m_filterErrors.insert(filter, ok ? QString()
                                                  : (message.isEmpty() ? tr("Invalid display filter") : message));
                 sync();
             });
}
