// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2022-2026 sbrown7792 and MultiPCAPSearch contributors

#include "capturefollower.h"

#include <QFileInfo>
#include <QProcess>

namespace
{
    // Capture headers are often byte-identical across files (same magic, snap
    // length, pcapng SHB/IDB), so compare enough to include some packets.
    constexpr qint64 headBytes = 4096;
    constexpr qint64 chunkBytes = 256 * 1024;
    constexpr qint64 maxQueuedBytes = 1024 * 1024;   // don't buffer a whole big file in memory
    constexpr int notifyDelayMs = 200;
}

CaptureFollower::CaptureFollower(const QString &tshark, const QString &file, const QStringList &filters, Mode mode,
                                 QObject *parent)
    : QObject(parent)
    , m_tshark(tshark)
    , m_file(file)
    , m_filters(filters)
    , m_mode(mode)
{
    Q_ASSERT(mode == Mode::MultiFilter || filters.size() == 1);

    m_poll.setInterval(500);
    connect(&m_poll, &QTimer::timeout, this, &CaptureFollower::poll);

    m_notify.setSingleShot(true);
    m_notify.setInterval(notifyDelayMs);
    connect(&m_notify, &QTimer::timeout, this, &CaptureFollower::changed);
}

CaptureFollower::~CaptureFollower()
{
    stopProcess();
}

QString CaptureFollower::expressionFor(const QString &filter)
{
    // "!(!(x))" turns any filter, even a bare field or protocol name, into a
    // true/false test that tshark prints as a check mark or nothing.
    const QString trimmed = filter.trimmed();
    return QStringLiteral("!(!(%1))").arg(trimmed.isEmpty() ? QStringLiteral("frame") : trimmed);
}

void CaptureFollower::start()
{
    restart();
    m_poll.start();
}

void CaptureFollower::startProcess()
{
    QStringList args{QStringLiteral("-l"), QStringLiteral("-n"), QStringLiteral("-r"), QStringLiteral("-"),
                     QStringLiteral("-T"), QStringLiteral("fields")};
    if (m_mode == Mode::MultiFilter)
    {
        args << QStringLiteral("-E") << QStringLiteral("separator=/t");
        for (const QString &filter : std::as_const(m_filters))
            args << QStringLiteral("-e") << expressionFor(filter);
    }
    else
    {
        args << QStringLiteral("-e") << QStringLiteral("frame.number");
        if (!m_filters.first().trimmed().isEmpty())
            args << QStringLiteral("-Y") << m_filters.first().trimmed();
    }

    m_process = new QProcess(this);
    connect(m_process, &QProcess::started, this, &CaptureFollower::pump);
    connect(m_process, &QProcess::bytesWritten, this, &CaptureFollower::pump);
    connect(m_process, &QProcess::readyReadStandardOutput, this, &CaptureFollower::readOutput);
    connect(m_process, &QProcess::readyReadStandardError, this, [this]() {
        m_stdErr += m_process->readAllStandardError();
    });
    connect(m_process, &QProcess::finished, this, [this](int exitCode, QProcess::ExitStatus) {
        // tshark only stops reading stdin on an error (we never close it).
        readOutput();
        m_stdErr += m_process->readAllStandardError();
        const QString stdErr = QString::fromLocal8Bit(m_stdErr).trimmed();
        fail(stdErr.isEmpty() ? tr("tshark stopped unexpectedly (exit code %1)").arg(exitCode) : stdErr);
    });
    connect(m_process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        if (error == QProcess::FailedToStart)
            fail(tr("Could not run tshark at \"%1\": %2").arg(m_tshark, m_process->errorString()));
    });

    m_process->start(m_tshark, args);
}

void CaptureFollower::stopProcess()
{
    if (!m_process)
        return;
    m_process->disconnect(this);
    m_process->kill();
    m_process->waitForFinished(1000);
    // May be called from one of the process's own signals, so don't delete it here.
    m_process->deleteLater();
    m_process = nullptr;
}

void CaptureFollower::restart()
{
    stopProcess();
    m_input.close();
    m_offset = 0;
    m_head.clear();
    m_partialLine.clear();
    m_stdErr.clear();
    m_counts = QList<qint64>(m_filters.size(), 0);
    m_caughtUp = false;
    m_error.clear();

    m_input.setFileName(m_file);
    if (!m_input.open(QIODevice::ReadOnly | QIODevice::Unbuffered))
    {
        fail(tr("Could not open %1: %2").arg(m_file, m_input.errorString()));
        return;
    }

    startProcess();
    markChanged();
}

void CaptureFollower::poll()
{
    if (!m_error.isEmpty() && !m_input.isOpen())
    {
        // The file couldn't be opened; it may have appeared since.
        if (QFileInfo::exists(m_file))
            restart();
        return;
    }
    if (!m_error.isEmpty())
        return;

    // Check the path, not our open handle: a replaced file is a new file.
    const QFileInfo info(m_file);
    if (!info.exists())
        return;   // e.g. mid-rotation; keep what we have
    if (info.size() < m_offset)
    {
        restart();
        return;
    }
    if (!m_head.isEmpty())
    {
        QFile current(m_file);
        if (current.open(QIODevice::ReadOnly) && current.read(m_head.size()) != m_head)
        {
            restart();
            return;
        }
    }

    if (info.size() > m_offset)
        pump();

    // Caught up = done with the backlog that was in the file when we started;
    // from then on we're live, even while new packets keep arriving.
    if (!m_caughtUp && m_offset >= info.size())
    {
        m_caughtUp = true;
        markChanged();
    }
}

void CaptureFollower::pump()
{
    if (!m_process || m_process->state() != QProcess::Running || !m_error.isEmpty())
        return;

    while (m_process->bytesToWrite() < maxQueuedBytes)
    {
        if (!m_input.seek(m_offset))
            break;
        const QByteArray chunk = m_input.read(chunkBytes);
        if (chunk.isEmpty())
            break;

        if (m_head.size() < headBytes)
            m_head += chunk.left(headBytes - m_head.size());
        m_process->write(chunk);
        m_offset += chunk.size();
    }
}

void CaptureFollower::readOutput()
{
    if (!m_process)
        return;

    const QByteArray data = m_partialLine + m_process->readAllStandardOutput();
    const int lastNewline = data.lastIndexOf('\n');
    if (lastNewline < 0)
    {
        m_partialLine = data;
        return;
    }
    m_partialLine = data.mid(lastNewline + 1);

    const QList<QByteArray> lines = data.left(lastNewline).split('\n');
    for (QByteArray line : lines)
    {
        if (line.endsWith('\r'))
            line.chop(1);

        if (m_mode == Mode::SingleFilter)
        {
            if (!line.isEmpty())
                ++m_counts[0];
            continue;
        }

        // One column per filter: a check mark if it matched, empty if not.
        const QList<QByteArray> fields = line.split('\t');
        for (int i = 0; i < fields.size() && i < m_counts.size(); ++i)
        {
            if (!fields.at(i).isEmpty())
                ++m_counts[i];
        }
    }
    markChanged();
}

void CaptureFollower::fail(const QString &message)
{
    m_error = message;
    stopProcess();
    markChanged();
}

void CaptureFollower::markChanged()
{
    if (!m_notify.isActive())
        m_notify.start();
}
