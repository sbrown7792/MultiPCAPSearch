// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2022-2026 sbrown7792 and MultiPCAPSearch contributors

#ifndef CAPTUREFOLLOWER_H
#define CAPTUREFOLLOWER_H

#include <QByteArray>
#include <QFile>
#include <QList>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QTimer>

class QProcess;

// Keeps counting packets in a capture file while something (dumpcap,
// Wireshark, tcpdump, ...) is still appending to it.
//
// One long-running tshark reads the capture from its stdin ("-r -"), and we
// feed it the file's bytes as they appear on disk, the way "tail -f" would.
// tshark dissects the stream exactly as it would the finished file (so
// stateful filters such as tcp.analysis.* and frame.number stay correct) and
// simply waits when it reaches a half-written packet.
//
// MultiFilter mode (tshark 4.4+) evaluates several display filters in one
// process, printing one "!(!(filter))" expression column per filter.
// SingleFilter mode works with any tshark: one filter, applied with -Y.
//
// If the file shrinks or its first bytes change (it was truncated or
// replaced), counting restarts from the beginning.
class CaptureFollower : public QObject
{
    Q_OBJECT

public:
    enum class Mode { MultiFilter, SingleFilter };

    CaptureFollower(const QString &tshark, const QString &file, const QStringList &filters, Mode mode,
                    QObject *parent = nullptr);
    ~CaptureFollower() override;

    void start();

    QString file() const { return m_file; }
    QStringList filters() const { return m_filters; }
    Mode mode() const { return m_mode; }

    // Matching packets so far, one per filter (same order as filters()).
    QList<qint64> counts() const { return m_counts; }

    // True once the packets that were already in the file have been handed to
    // tshark; it stays true while new packets keep arriving.
    bool caughtUp() const { return m_caughtUp; }
    qint64 bytesRead() const { return m_offset; }

    // Non-empty if tshark failed; counting has stopped.
    QString error() const { return m_error; }

    // How often the file is checked for new data.
    void setPollInterval(int ms) { m_poll.setInterval(ms); }

    // Builds the tshark display-filter expression used for one filter in
    // MultiFilter mode. An empty filter matches every packet.
    static QString expressionFor(const QString &filter);

signals:
    // Emitted (at most every few hundred ms) when counts, caughtUp or error change.
    void changed();

private:
    void startProcess();
    void stopProcess();
    void restart();
    void poll();
    void pump();
    void readOutput();
    void fail(const QString &message);
    void markChanged();

    QString m_tshark;
    QString m_file;
    QStringList m_filters;
    Mode m_mode;

    QProcess *m_process = nullptr;
    QFile m_input;
    qint64 m_offset = 0;
    QByteArray m_head;          // first bytes of the file, to notice replacement
    QByteArray m_partialLine;
    QByteArray m_stdErr;
    QList<qint64> m_counts;
    bool m_caughtUp = false;
    QString m_error;

    QTimer m_poll;
    QTimer m_notify;
};

#endif // CAPTUREFOLLOWER_H
