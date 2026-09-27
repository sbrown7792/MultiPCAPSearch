#include <QApplication>
#include <QCheckBox>
#include <QDir>
#include <QFileDialog>
#include <QInputDialog>
#include <QLineEdit>
#include <QSettings>
#include <QSignalSpy>
#include <QTableWidget>
#include <QTemporaryDir>
#include <QTest>
#include <QTimer>

#include "mainwindow.h"
#include "searchengine.h"
#include "testpcap.h"
#include "tsharklocator.h"

namespace
{
    // Test captures: (packets, every Nth packet is DNS). Expected counts follow from these.
    struct Capture { const char *name; int packets; int dnsEvery; };
    const Capture captures[] = {
        {"a.pcap", 100, 4},     // 25 DNS, 50 from 10.0.0.1
        {"b.pcap", 60, 3},      // 20 DNS, 30 from 10.0.0.1
        {"c.pcap", 41, 10},     //  5 DNS, 21 from 10.0.0.1
    };

    int expectedCount(const Capture &c, const QString &filter)
    {
        if (filter.isEmpty())
            return c.packets;
        if (filter == QLatin1String("udp.dstport == 53"))
            return (c.packets + c.dnsEvery - 1) / c.dnsEvery;
        if (filter == QLatin1String("ip.src == 10.0.0.1"))
            return (c.packets + 1) / 2;
        return -1;
    }
}

class TestMultiPcapSearch : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanup();

    void countsMatchingPackets_data();
    void countsMatchingPackets();
    void invalidFilterIsAnError();
    void missingTsharkIsAnError();
    void cachedResultIsReturnedImmediately();
    void cacheIsInvalidatedWhenFileChanges();
    void duplicateRequestsAreCoalesced();
    void respectsConcurrencyLimit();
    void cancelAllStopsEverything();

    void editingTablesDuringSearchDoesNotCrash();
    void remembersLastBrowsedDirectory();

private:
    QString capturePath(const Capture &c) const { return m_dir.filePath(QString::fromLatin1(c.name)); }
    SearchResult runOne(SearchEngine &engine, const QString &file, const QString &filter);

    QTemporaryDir m_dir;
    QString m_tshark;
};

void TestMultiPcapSearch::initTestCase()
{
    QCoreApplication::setOrganizationName(QStringLiteral("MultiPCAPSearchTests"));
    QCoreApplication::setApplicationName(QStringLiteral("MultiPCAPSearchTests"));
    QSettings().clear();

    QVERIFY(m_dir.isValid());
    for (const Capture &c : captures)
        QVERIFY(writeTestPcap(capturePath(c), c.packets, c.dnsEvery));

    m_tshark = TsharkLocator::find(qEnvironmentVariable("MULTIPCAPSEARCH_TSHARK"));
    if (m_tshark.isEmpty())
    {
        if (qEnvironmentVariableIsSet("MULTIPCAPSEARCH_REQUIRE_TSHARK"))
            QFAIL("tshark not found, but MULTIPCAPSEARCH_REQUIRE_TSHARK is set");
        QSKIP("tshark not found; set MULTIPCAPSEARCH_TSHARK or install Wireshark");
    }
    qInfo() << "Using tshark at" << m_tshark;
}

void TestMultiPcapSearch::cleanup()
{
    QSettings().clear();
}

SearchResult TestMultiPcapSearch::runOne(SearchEngine &engine, const QString &file, const QString &filter)
{
    QSignalSpy spy(&engine, &SearchEngine::resultReady);
    engine.search(file, filter);
    if (spy.isEmpty() && !spy.wait(60000))
        return SearchResult{SearchResult::Error, 0, QStringLiteral("timed out")};
    return spy.last().at(2).value<SearchResult>();
}

void TestMultiPcapSearch::countsMatchingPackets_data()
{
    QTest::addColumn<int>("capture");
    QTest::addColumn<QString>("filter");
    for (int i = 0; i < 3; ++i)
    {
        for (const char *filter : {"", "udp.dstport == 53", "ip.src == 10.0.0.1"})
            QTest::addRow("%s [%s]", captures[i].name, filter) << i << QString::fromLatin1(filter);
    }
}

void TestMultiPcapSearch::countsMatchingPackets()
{
    QFETCH(int, capture);
    QFETCH(QString, filter);

    SearchEngine engine;
    engine.setTsharkPath(m_tshark);
    const SearchResult result = runOne(engine, capturePath(captures[capture]), filter);

    QCOMPARE(result.status, SearchResult::Ok);
    QCOMPARE(result.count, expectedCount(captures[capture], filter));
}

void TestMultiPcapSearch::invalidFilterIsAnError()
{
    SearchEngine engine;
    engine.setTsharkPath(m_tshark);
    const SearchResult result = runOne(engine, capturePath(captures[0]), QStringLiteral("notaprotocol.field == 1"));
    QCOMPARE(result.status, SearchResult::Error);
    QVERIFY2(!result.message.isEmpty(), "tshark's complaint should be reported");
}

void TestMultiPcapSearch::missingTsharkIsAnError()
{
    SearchEngine engine;
    engine.setTsharkPath(m_dir.filePath(QStringLiteral("no-such-tshark")));
    const SearchResult result = runOne(engine, capturePath(captures[0]), QString());
    QCOMPARE(result.status, SearchResult::Error);
    QVERIFY(result.message.contains(QLatin1String("no-such-tshark")));
    QVERIFY2(!engine.cachedResult(capturePath(captures[0]), QString(), nullptr), "launch failures must not be cached");
}

void TestMultiPcapSearch::cachedResultIsReturnedImmediately()
{
    SearchEngine engine;
    engine.setTsharkPath(m_tshark);
    const QString file = capturePath(captures[1]);
    QCOMPARE(runOne(engine, file, QString()).count, 60);

    QSignalSpy started(&engine, &SearchEngine::searchStarted);
    QSignalSpy results(&engine, &SearchEngine::resultReady);
    engine.search(file, QString());
    QCOMPARE(results.size(), 1);   // synchronous
    QCOMPARE(started.size(), 0);   // no new tshark run
    QCOMPARE(results.first().at(2).value<SearchResult>().count, 60);

    engine.clearCache();
    QVERIFY(!engine.cachedResult(file, QString(), nullptr));
}

void TestMultiPcapSearch::cacheIsInvalidatedWhenFileChanges()
{
    SearchEngine engine;
    engine.setTsharkPath(m_tshark);
    const QString file = m_dir.filePath(QStringLiteral("changing.pcap"));
    QVERIFY(writeTestPcap(file, 10, 2));
    QCOMPARE(runOne(engine, file, QString()).count, 10);

    QVERIFY(writeTestPcap(file, 12, 2));
    QVERIFY(!engine.cachedResult(file, QString(), nullptr));
    QCOMPARE(runOne(engine, file, QString()).count, 12);
}

void TestMultiPcapSearch::duplicateRequestsAreCoalesced()
{
    SearchEngine engine;
    engine.setTsharkPath(m_tshark);
    QSignalSpy results(&engine, &SearchEngine::resultReady);
    for (int i = 0; i < 5; ++i)
        engine.search(capturePath(captures[0]), QStringLiteral("udp"));
    QCOMPARE(engine.pendingJobs(), 1);
    QVERIFY(results.wait(60000));
    QCOMPARE(results.size(), 1);
}

void TestMultiPcapSearch::respectsConcurrencyLimit()
{
    SearchEngine engine;
    engine.setTsharkPath(m_tshark);
    engine.setMaxConcurrent(2);

    int running = 0;
    int maxRunning = 0;
    int finished = 0;
    connect(&engine, &SearchEngine::searchStarted, this, [&]() { maxRunning = qMax(maxRunning, ++running); });
    connect(&engine, &SearchEngine::resultReady, this, [&]() { --running; ++finished; });

    for (int i = 0; i < 6; ++i)
        engine.search(capturePath(captures[i % 3]), QStringLiteral("frame.number > %1").arg(i));
    QCOMPARE(engine.pendingJobs(), 6);

    QTRY_COMPARE_WITH_TIMEOUT(finished, 6, 120000);
    QCOMPARE(maxRunning, 2);
    QCOMPARE(engine.pendingJobs(), 0);
}

void TestMultiPcapSearch::cancelAllStopsEverything()
{
    SearchEngine engine;
    engine.setTsharkPath(m_tshark);
    engine.setMaxConcurrent(1);

    QSignalSpy results(&engine, &SearchEngine::resultReady);
    for (int i = 0; i < 5; ++i)
        engine.search(capturePath(captures[0]), QStringLiteral("frame.len > %1").arg(i));
    engine.cancelAll();
    QCOMPARE(engine.pendingJobs(), 0);

    QTest::qWait(1500);
    QCOMPARE(results.size(), 0);
}

// Regression test for issue #2: adding (or removing) captures and filters while
// a live search is running used to crash, because worker threads wrote to table
// items that the GUI thread had deleted or reallocated.
void TestMultiPcapSearch::editingTablesDuringSearchDoesNotCrash()
{
    QSettings().setValue(QStringLiteral("tsharkPath"), m_tshark);
    QSettings().setValue(QStringLiteral("maxConcurrent"), 2);   // keep work queued up

    MainWindow window;
    auto *results = window.findChild<QTableWidget *>(QStringLiteral("resultsTable"));
    auto *filters = window.findChild<QTableWidget *>(QStringLiteral("filterTable"));
    auto *live = window.findChild<QCheckBox *>(QStringLiteral("liveSearch"));
    QVERIFY(results && filters && live);

    live->setChecked(true);
    window.addFilterRow(QStringLiteral("All"), QString());
    window.addFilterRow(QStringLiteral("DNS"), QStringLiteral("udp.dstport == 53"));
    window.addPcapFiles({capturePath(captures[0]), capturePath(captures[1])}, false);
    // Live search only fires for new captures and edited filters; kick off the rest.
    filters->item(0, 1)->setText(QString());
    filters->item(1, 1)->setText(QStringLiteral("udp.dstport == 53"));

    // While those run: add a capture, remove one, add a filter, delete one, edit one.
    window.addPcapFiles({capturePath(captures[2])}, false);
    results->removeRow(0);   // a.pcap
    window.addFilterRow(QStringLiteral("Host1"), QString());
    filters->item(2, 1)->setText(QStringLiteral("ip.src == 10.0.0.1"));
    filters->item(0, 0)->setCheckState(Qt::Checked);
    QMetaObject::invokeMethod(&window, "on_deleteFilter_clicked");
    window.addPcapFiles({capturePath(captures[0])}, false);

    // Remaining: captures b, c, a  x  filters DNS, Host1.
    QCOMPARE(results->rowCount(), 3);
    QCOMPARE(filters->rowCount(), 2);
    QCOMPARE(results->columnCount(), 3);

    const int order[] = {1, 2, 0};
    for (int row = 0; row < 3; ++row)
    {
        for (int f = 0; f < 2; ++f)
        {
            const QString filter = filters->item(f, 1)->text();
            const QString expected = QString::number(expectedCount(captures[order[row]], filter));
            QTRY_COMPARE_WITH_TIMEOUT(results->item(row, f + 1)->text(), expected, 120000);
        }
    }
}

// Issue #1: the file dialog should reopen in the last directory used.
void TestMultiPcapSearch::remembersLastBrowsedDirectory()
{
    QSettings().setValue(QStringLiteral("tsharkPath"), m_tshark);
    QSettings().setValue(QStringLiteral("lastPcapDir"), QDir::tempPath());
    MainWindow window;
    auto *results = window.findChild<QTableWidget *>(QStringLiteral("resultsTable"));

    // Drives the modal dialogs opened by "Add PCAP Files": records where the file
    // dialog started, picks b.pcap, and accepts the friendly-name prompt.
    QString dialogDir;
    QTimer driver;
    driver.setInterval(20);
    connect(&driver, &QTimer::timeout, this, [&]() {
        QWidget *modal = QApplication::activeModalWidget();
        if (auto *files = qobject_cast<QFileDialog *>(modal))
        {
            dialogDir = files->directory().absolutePath();
            if (auto *edit = files->findChild<QLineEdit *>(QStringLiteral("fileNameEdit")))
                edit->setText(capturePath(captures[1]));
            static_cast<QDialog *>(files)->done(QDialog::Accepted);
        }
        else if (auto *name = qobject_cast<QInputDialog *>(modal))
        {
            name->accept();
        }
    });
    driver.start();

    QMetaObject::invokeMethod(&window, "on_addPCAP_clicked");
    QCOMPARE(QDir(dialogDir), QDir(QDir::tempPath()));
    QCOMPARE(results->rowCount(), 1);
    QCOMPARE(QDir(QSettings().value(QStringLiteral("lastPcapDir")).toString()), QDir(m_dir.path()));

    QMetaObject::invokeMethod(&window, "on_addPCAP_clicked");
    QCOMPARE(QDir(dialogDir), QDir(m_dir.path()));
    QCOMPARE(results->rowCount(), 2);
}

QTEST_MAIN(TestMultiPcapSearch)
#include "tst_multipcapsearch.moc"
