#ifndef SEARCHENGINE_H
#define SEARCHENGINE_H

#include <QDateTime>
#include <QHash>
#include <QList>
#include <QObject>
#include <QString>

class QProcess;

// Outcome of applying one display filter to one capture file.
struct SearchResult
{
    enum Status { Ok, Warning, Error };

    Status status = Error;
    qint64 count = 0;       // number of matching packets (valid unless status == Error)
    QString message;        // tshark's stderr output, or an explanation of the failure
};

// Runs tshark over (capture file, display filter) pairs.
//
// Every job is an asynchronous QProcess owned by this object and driven by the
// GUI thread's event loop, so no widget or shared state is ever touched from a
// worker thread. At most maxConcurrent() tshark processes run at once; the rest
// wait in a queue. Results are cached per (file, filter) and invalidated when the
// capture file changes on disk.
//
// Callers identify jobs purely by (file, filter) values, never by pointers to
// UI items, so rows and columns can be added or removed while a search runs.
class SearchEngine : public QObject
{
    Q_OBJECT

public:
    explicit SearchEngine(QObject *parent = nullptr);
    ~SearchEngine() override;

    void setTsharkPath(const QString &path);
    QString tsharkPath() const;

    void setMaxConcurrent(int max);
    int maxConcurrent() const;

    // Returns true and fills *result if a still-valid cached result exists.
    bool cachedResult(const QString &file, const QString &filter, SearchResult *result) const;

    // Queues a search unless it is cached, already queued or already running.
    // Emits resultReady() straight away for a cached result.
    void search(const QString &file, const QString &filter);

    // Drops queued jobs and kills running ones. No results are emitted for them.
    void cancelAll();

    void clearCache();

    // Number of queued plus running jobs.
    int pendingJobs() const;

signals:
    void searchStarted(const QString &file, const QString &filter);
    void resultReady(const QString &file, const QString &filter, const SearchResult &result);
    void pendingJobsChanged(int pending);

private:
    struct Job
    {
        QString file;
        QString filter;
    };

    struct CacheEntry
    {
        QDateTime modified;
        qint64 size = -1;
        SearchResult result;
    };

    struct Running
    {
        Job job;
        qint64 lines = 0;
        QByteArray stdErr;
    };

    static QString key(const QString &file, const QString &filter);
    void startNextJobs();
    void startJob(const Job &job);
    void finishJob(QProcess *process, int exitCode, bool crashed);

    QString m_tshark;
    int m_maxConcurrent;
    QList<Job> m_queue;
    QHash<QProcess *, Running> m_running;
    QHash<QString, CacheEntry> m_cache;
};

#endif // SEARCHENGINE_H
