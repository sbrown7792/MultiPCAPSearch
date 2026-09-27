#include "searchengine.h"

#include <QFileInfo>
#include <QProcess>
#include <QThread>

SearchEngine::SearchEngine(QObject *parent)
    : QObject(parent)
    , m_maxConcurrent(qMax(1, QThread::idealThreadCount()))
{
}

SearchEngine::~SearchEngine()
{
    // Don't leave tshark processes running (or zombied) after we're gone. This
    // includes ones cancelAll() already killed but that haven't exited yet.
    for (QProcess *process : findChildren<QProcess *>(Qt::FindDirectChildrenOnly))
    {
        process->disconnect();
        process->kill();
        process->waitForFinished(2000);
    }
}

void SearchEngine::setTsharkPath(const QString &path)
{
    m_tshark = path;
}

QString SearchEngine::tsharkPath() const
{
    return m_tshark;
}

void SearchEngine::setMaxConcurrent(int max)
{
    m_maxConcurrent = qMax(1, max);
    startNextJobs();
}

int SearchEngine::maxConcurrent() const
{
    return m_maxConcurrent;
}

QString SearchEngine::key(const QString &file, const QString &filter)
{
    // A NUL can't appear in a path, so the pair maps to a unique key.
    return file + QChar(0) + filter;
}

bool SearchEngine::cachedResult(const QString &file, const QString &filter, SearchResult *result) const
{
    const auto it = m_cache.constFind(key(file, filter));
    if (it == m_cache.cend())
        return false;

    // The capture may have been overwritten (e.g. a rolling capture) since we searched it.
    const QFileInfo info(file);
    if (info.lastModified() != it->modified || info.size() != it->size)
        return false;

    if (result)
        *result = it->result;
    return true;
}

void SearchEngine::search(const QString &file, const QString &filter)
{
    SearchResult cached;
    if (cachedResult(file, filter, &cached))
    {
        emit resultReady(file, filter, cached);
        return;
    }

    for (const Job &job : std::as_const(m_queue))
    {
        if (job.file == file && job.filter == filter)
            return;
    }
    for (const Running &running : std::as_const(m_running))
    {
        if (running.job.file == file && running.job.filter == filter)
            return;
    }

    m_queue.append({file, filter});
    emit pendingJobsChanged(pendingJobs());
    startNextJobs();
}

void SearchEngine::cancelAll()
{
    m_queue.clear();

    const QList<QProcess *> processes = m_running.keys();
    m_running.clear();
    for (QProcess *process : processes)
    {
        process->disconnect(this);
        connect(process, &QProcess::finished, process, &QObject::deleteLater);
        connect(process, &QProcess::errorOccurred, process, &QObject::deleteLater);
        process->kill();
    }

    emit pendingJobsChanged(0);
}

void SearchEngine::clearCache()
{
    m_cache.clear();
}

int SearchEngine::pendingJobs() const
{
    return m_queue.size() + m_running.size();
}

void SearchEngine::startNextJobs()
{
    while (!m_queue.isEmpty() && m_running.size() < m_maxConcurrent)
        startJob(m_queue.takeFirst());
}

void SearchEngine::startJob(const Job &job)
{
    QProcess *process = new QProcess(this);
    m_running.insert(process, Running{job, 0, {}});

    // Print one short line per matching packet and count the lines as they
    // stream in, so memory use stays flat no matter how large the capture is.
    QStringList args{"-n", "-r", job.file, "-T", "fields", "-e", "frame.number"};
    if (!job.filter.trimmed().isEmpty())
        args << "-Y" << job.filter;

    connect(process, &QProcess::readyReadStandardOutput, this, [this, process]() {
        auto it = m_running.find(process);
        if (it != m_running.end())
            it->lines += process->readAllStandardOutput().count('\n');
    });
    connect(process, &QProcess::readyReadStandardError, this, [this, process]() {
        auto it = m_running.find(process);
        if (it != m_running.end())
            it->stdErr += process->readAllStandardError();
    });
    connect(process, &QProcess::finished, this, [this, process](int exitCode, QProcess::ExitStatus status) {
        finishJob(process, exitCode, status == QProcess::CrashExit);
    });
    connect(process, &QProcess::errorOccurred, this, [this, process](QProcess::ProcessError error) {
        // Only a failed start never reaches finished(); everything else is handled there.
        if (error == QProcess::FailedToStart)
            finishJob(process, -1, true);
    });

    emit searchStarted(job.file, job.filter);
    process->start(m_tshark, args, QIODevice::ReadOnly);
}

void SearchEngine::finishJob(QProcess *process, int exitCode, bool crashed)
{
    auto it = m_running.find(process);
    if (it == m_running.end())
        return;

    Running running = it.value();
    m_running.erase(it);

    running.lines += process->readAllStandardOutput().count('\n');
    running.stdErr += process->readAllStandardError();
    const QString stdErr = QString::fromLocal8Bit(running.stdErr).trimmed();

    SearchResult result;
    if (process->error() == QProcess::FailedToStart)
    {
        result.status = SearchResult::Error;
        result.message = m_tshark.isEmpty()
            ? tr("tshark was not found. Install Wireshark, or use Settings > Locate tshark...")
            : tr("Could not run tshark at \"%1\": %2").arg(m_tshark, process->errorString());
    }
    else if (crashed || exitCode != 0)
    {
        result.status = SearchResult::Error;
        result.message = stdErr.isEmpty()
            ? tr("tshark exited with code %1").arg(exitCode)
            : stdErr;
    }
    else
    {
        result.status = stdErr.isEmpty() ? SearchResult::Ok : SearchResult::Warning;
        result.count = running.lines;
        result.message = stdErr;
    }

    process->deleteLater();

    // A failure to launch says nothing about the file/filter pair, so don't cache it.
    if (process->error() != QProcess::FailedToStart)
    {
        const QFileInfo info(running.job.file);
        m_cache.insert(key(running.job.file, running.job.filter),
                       CacheEntry{info.lastModified(), info.size(), result});
    }

    emit resultReady(running.job.file, running.job.filter, result);
    startNextJobs();
    emit pendingJobsChanged(pendingJobs());
}
