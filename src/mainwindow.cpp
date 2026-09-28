// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2022-2026 sbrown7792 and MultiPCAPSearch contributors

#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "tsharklocator.h"

#include <QCloseEvent>
#include <QDesktopServices>
#include <QDir>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QInputDialog>
#include <QLabel>
#include <QMessageBox>
#include <QMimeData>
#include <QProcess>
#include <QSaveFile>
#include <QSettings>
#include <QSignalBlocker>
#include <QTextStream>
#include <QThread>
#include <QUrl>

namespace
{
    // Item data roles used in the results table.
    constexpr int FileRole = Qt::UserRole;          // column 0: absolute path of the capture
    constexpr int StateRole = Qt::UserRole + 1;     // result cells: MainWindow::CellState

    const QString captureFileFilter = QStringLiteral(
        "Capture files (*.pcap *.pcapng *.cap *.pcap.gz *.pcapng.gz *.cap.gz *.trc *.snoop *.erf);;All files (*)");

    QColor errorColor() { return QColor(220, 40, 40, 110); }
    QColor warningColor() { return QColor(230, 170, 0, 110); }

    QString csvField(QString text)
    {
        if (text.contains(',') || text.contains('"') || text.contains('\n'))
            text = '"' + text.replace('"', QStringLiteral("\"\"")) + '"';
        return text;
    }
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , m_tsharkLabel(new QLabel(this))
{
    ui->setupUi(this);
    setWindowTitle(QStringLiteral("MultiPCAPSearch %1").arg(QCoreApplication::applicationVersion()));

    ui->filterTable->setColumnWidth(0, 160);
    ui->resultsTable->setColumnWidth(0, 220);
    ui->splitter->setStretchFactor(0, 2);
    ui->splitter->setStretchFactor(1, 3);
    ui->statusbar->addPermanentWidget(m_tsharkLabel);

    connect(ui->actionAddPcaps, &QAction::triggered, this, &MainWindow::on_addPCAP_clicked);
    connect(ui->actionExportCsv, &QAction::triggered, this, &MainWindow::on_exportCsv_clicked);
    connect(ui->actionQuit, &QAction::triggered, this, &QWidget::close);

    // Connected exactly once; the engine reports results by (file, filter)
    // value, so there are no pointers into the tables to go stale.
    connect(&m_engine, &SearchEngine::searchStarted, this, &MainWindow::onSearchStarted);
    connect(&m_engine, &SearchEngine::resultReady, this, &MainWindow::onResultReady);
    connect(&m_engine, &SearchEngine::pendingJobsChanged, this, &MainWindow::onPendingJobsChanged);

    // Renaming a capture only changes its label; nothing to re-search.
    connect(ui->resultsTable, &QTableWidget::itemChanged, this, [this](QTableWidgetItem *item) {
        if (item->column() == 0 && item->text().trimmed().isEmpty())
            item->setText(QFileInfo(item->data(FileRole).toString()).completeBaseName());
    });

    loadSettings();
}

MainWindow::~MainWindow()
{
    // Don't leave a "tshark --version" probe running past our lifetime.
    for (QProcess *probe : findChildren<QProcess *>(Qt::FindDirectChildrenOnly))
    {
        probe->disconnect(this);
        probe->kill();
        probe->waitForFinished(1000);
    }
    delete ui;
}

// ---------------------------------------------------------------------------
// Table helpers
// ---------------------------------------------------------------------------

QString MainWindow::pcapFile(int pcapRow) const
{
    const QTableWidgetItem *item = ui->resultsTable->item(pcapRow, 0);
    return item ? item->data(FileRole).toString() : QString();
}

QString MainWindow::filterText(int filterRow) const
{
    const QTableWidgetItem *item = ui->filterTable->item(filterRow, 1);
    return item ? item->text().trimmed() : QString();
}

QTableWidgetItem *MainWindow::resultCell(int pcapRow, int filterRow) const
{
    return ui->resultsTable->item(pcapRow, filterRow + 1);
}

template <typename Fn>
void MainWindow::forEachMatchingCell(const QString &file, const QString &filter, Fn fn)
{
    for (int filterRow = 0; filterRow < ui->filterTable->rowCount(); ++filterRow)
    {
        if (filterText(filterRow) != filter)
            continue;
        for (int pcapRow = 0; pcapRow < ui->resultsTable->rowCount(); ++pcapRow)
        {
            if (pcapFile(pcapRow) != file)
                continue;
            if (QTableWidgetItem *cell = resultCell(pcapRow, filterRow))
                fn(cell);
        }
    }
}

QList<int> MainWindow::rowsToRemove(QTableWidget *table)
{
    QList<int> rows;
    for (int row = 0; row < table->rowCount(); ++row)
    {
        const QTableWidgetItem *item = table->item(row, 0);
        if (item && item->checkState() == Qt::Checked)
            rows << row;
    }

    if (rows.isEmpty())
    {
        const QModelIndexList selected = table->selectionModel()->selectedRows();
        for (const QModelIndex &index : selected)
            rows << index.row();
    }

    std::sort(rows.begin(), rows.end(), std::greater<int>());
    return rows;
}

void MainWindow::resetCell(QTableWidgetItem *cell)
{
    cell->setText(QString());
    cell->setToolTip(QString());
    cell->setData(Qt::BackgroundRole, QVariant());
    cell->setData(StateRole, Idle);
}

void MainWindow::resetColumn(int filterRow)
{
    for (int pcapRow = 0; pcapRow < ui->resultsTable->rowCount(); ++pcapRow)
    {
        if (QTableWidgetItem *cell = resultCell(pcapRow, filterRow))
            resetCell(cell);
    }
}

void MainWindow::resetPendingCells()
{
    for (int pcapRow = 0; pcapRow < ui->resultsTable->rowCount(); ++pcapRow)
    {
        for (int filterRow = 0; filterRow < ui->filterTable->rowCount(); ++filterRow)
        {
            QTableWidgetItem *cell = resultCell(pcapRow, filterRow);
            const int state = cell ? cell->data(StateRole).toInt() : Idle;
            if (state == Queued || state == Running)
                resetCell(cell);
        }
    }
}

void MainWindow::setCellResult(QTableWidgetItem *cell, const SearchResult &result)
{
    cell->setData(StateRole, Done);
    cell->setToolTip(result.message);

    switch (result.status)
    {
    case SearchResult::Ok:
        cell->setText(QString::number(result.count));
        cell->setData(Qt::BackgroundRole, QVariant());
        break;
    case SearchResult::Warning:
        cell->setText(QString::number(result.count) + QStringLiteral(" ⚠"));
        cell->setData(Qt::BackgroundRole, warningColor());
        break;
    case SearchResult::Error:
        cell->setText(tr("Error"));
        cell->setData(Qt::BackgroundRole, errorColor());
        break;
    }
}

// ---------------------------------------------------------------------------
// Searching
// ---------------------------------------------------------------------------

void MainWindow::searchCell(int pcapRow, int filterRow)
{
    QTableWidgetItem *cell = resultCell(pcapRow, filterRow);
    const QString file = pcapFile(pcapRow);
    if (!cell || file.isEmpty())
        return;

    // Mark it queued first; a cached result is delivered synchronously and overwrites this.
    if (cell->data(StateRole).toInt() != Running)
    {
        cell->setText(tr("Queued..."));
        cell->setToolTip(QString());
        cell->setData(Qt::BackgroundRole, QVariant());
        cell->setData(StateRole, Queued);
    }
    m_engine.search(file, filterText(filterRow));
}

void MainWindow::searchAll()
{
    for (int pcapRow = 0; pcapRow < ui->resultsTable->rowCount(); ++pcapRow)
        searchRow(pcapRow);
}

void MainWindow::searchColumn(int filterRow)
{
    for (int pcapRow = 0; pcapRow < ui->resultsTable->rowCount(); ++pcapRow)
        searchCell(pcapRow, filterRow);
}

void MainWindow::searchRow(int pcapRow)
{
    for (int filterRow = 0; filterRow < ui->filterTable->rowCount(); ++filterRow)
        searchCell(pcapRow, filterRow);
}

void MainWindow::onSearchStarted(const QString &file, const QString &filter)
{
    forEachMatchingCell(file, filter, [](QTableWidgetItem *cell) {
        cell->setText(tr("Searching..."));
        cell->setData(StateRole, Running);
    });
}

void MainWindow::onResultReady(const QString &file, const QString &filter, const SearchResult &result)
{
    // If the capture was removed or the filter edited meanwhile, nothing matches and the
    // result is simply dropped (it stays cached in the engine for next time).
    forEachMatchingCell(file, filter, [this, &result](QTableWidgetItem *cell) {
        setCellResult(cell, result);
    });
}

void MainWindow::onPendingJobsChanged(int pending)
{
    ui->stopSearch->setEnabled(pending > 0);
    if (pending > 0)
        ui->statusbar->showMessage(tr("%n search(es) remaining...", nullptr, pending));
    else
        ui->statusbar->showMessage(tr("Done"), 3000);
}

void MainWindow::on_searchNow_clicked()
{
    if (m_engine.tsharkPath().isEmpty())
    {
        on_actionLocateTshark_triggered();
        if (m_engine.tsharkPath().isEmpty())
            return;
    }
    searchAll();
}

void MainWindow::on_stopSearch_clicked()
{
    m_engine.cancelAll();
    resetPendingCells();
    ui->statusbar->showMessage(tr("Search cancelled"), 3000);
}

void MainWindow::on_liveSearch_toggled(bool checked)
{
    ui->searchNow->setEnabled(!checked);
    if (checked && !m_loading)
        searchAll();
}

// ---------------------------------------------------------------------------
// Capture files
// ---------------------------------------------------------------------------

void MainWindow::on_addPCAP_clicked()
{
    QSettings settings;
    const QString startDir = settings.value(QStringLiteral("lastPcapDir"), QDir::homePath()).toString();

    const QStringList files = QFileDialog::getOpenFileNames(this, tr("Select PCAP Files"), startDir, captureFileFilter);
    if (files.isEmpty())
        return;

    // Remember where we were so the next dialog opens there (issue #1).
    settings.setValue(QStringLiteral("lastPcapDir"), QFileInfo(files.first()).absolutePath());

    addPcapFiles(files, files.size() == 1);
}

void MainWindow::addPcapFiles(const QStringList &files, bool askForName)
{
    for (const QString &path : files)
    {
        const QFileInfo info(path);
        const QString file = info.absoluteFilePath();
        QString name = info.completeBaseName();

        if (askForName)
        {
            bool ok = false;
            const QString entered = QInputDialog::getText(this, tr("Give this PCAP a name"), tr("Friendly name:"),
                                                          QLineEdit::Normal, name, &ok);
            if (!ok)
                continue;
            if (!entered.trimmed().isEmpty())
                name = entered.trimmed();
        }

        const int row = ui->resultsTable->rowCount();
        {
            const QSignalBlocker blocker(ui->resultsTable);
            ui->resultsTable->insertRow(row);

            auto *nameItem = new QTableWidgetItem(name);
            nameItem->setData(FileRole, file);
            nameItem->setToolTip(QDir::toNativeSeparators(file));
            nameItem->setCheckState(Qt::Unchecked);
            ui->resultsTable->setItem(row, 0, nameItem);

            for (int filterRow = 0; filterRow < ui->filterTable->rowCount(); ++filterRow)
            {
                auto *cell = new QTableWidgetItem();
                cell->setFlags(cell->flags() & ~Qt::ItemIsEditable);
                cell->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
                ui->resultsTable->setItem(row, filterRow + 1, cell);
            }
        }

        if (ui->liveSearch->isChecked())
            searchRow(row);
    }
}

void MainWindow::on_removePCAP_clicked()
{
    // Running searches for these files just finish into the cache; their
    // results no longer match any row, so nothing is written to the table.
    for (int row : rowsToRemove(ui->resultsTable))
        ui->resultsTable->removeRow(row);
}

void MainWindow::on_clearResults_clicked()
{
    m_engine.cancelAll();
    m_engine.clearCache();
    for (int filterRow = 0; filterRow < ui->filterTable->rowCount(); ++filterRow)
        resetColumn(filterRow);
}

void MainWindow::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls())
        event->acceptProposedAction();
}

void MainWindow::dropEvent(QDropEvent *event)
{
    QStringList files;
    for (const QUrl &url : event->mimeData()->urls())
    {
        if (url.isLocalFile() && QFileInfo(url.toLocalFile()).isFile())
            files << url.toLocalFile();
    }
    if (files.isEmpty())
        return;

    event->acceptProposedAction();
    addPcapFiles(files, false);
}

void MainWindow::on_exportCsv_clicked()
{
    QSettings settings;
    const QString startDir = settings.value(QStringLiteral("lastCsvDir"),
                                            settings.value(QStringLiteral("lastPcapDir"), QDir::homePath())).toString();
    const QString path = QFileDialog::getSaveFileName(this, tr("Export Results"),
                                                      QDir(startDir).filePath(QStringLiteral("results.csv")),
                                                      tr("CSV files (*.csv);;All files (*)"));
    if (path.isEmpty())
        return;
    settings.setValue(QStringLiteral("lastCsvDir"), QFileInfo(path).absolutePath());

    QSaveFile out(path);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        QMessageBox::warning(this, tr("Export Failed"), out.errorString());
        return;
    }

    QTextStream stream(&out);
    QStringList header{tr("Name"), tr("File")};
    for (int filterRow = 0; filterRow < ui->filterTable->rowCount(); ++filterRow)
    {
        const QTableWidgetItem *name = ui->filterTable->item(filterRow, 0);
        header << csvField(QStringLiteral("%1 [%2]").arg(name ? name->text() : QString(), filterText(filterRow)));
    }
    stream << header.join(',') << '\n';

    for (int pcapRow = 0; pcapRow < ui->resultsTable->rowCount(); ++pcapRow)
    {
        QStringList line{csvField(ui->resultsTable->item(pcapRow, 0)->text()),
                         csvField(QDir::toNativeSeparators(pcapFile(pcapRow)))};
        for (int filterRow = 0; filterRow < ui->filterTable->rowCount(); ++filterRow)
        {
            const QTableWidgetItem *cell = resultCell(pcapRow, filterRow);
            const bool done = cell && cell->data(StateRole).toInt() == Done;
            line << csvField(done ? cell->text().remove(QStringLiteral(" ⚠")) : QString());
        }
        stream << line.join(',') << '\n';
    }

    stream.flush();
    if (!out.commit())
        QMessageBox::warning(this, tr("Export Failed"), out.errorString());
    else
        ui->statusbar->showMessage(tr("Exported to %1").arg(QDir::toNativeSeparators(path)), 5000);
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

void MainWindow::on_addFilter_clicked()
{
    addFilterRow(tr("Filter%1").arg(ui->filterTable->rowCount() + 1), QString());
    const int row = ui->filterTable->rowCount() - 1;
    ui->filterTable->setCurrentCell(row, 1);
    ui->filterTable->editItem(ui->filterTable->item(row, 1));
}

void MainWindow::addFilterRow(const QString &name, const QString &filter)
{
    const int filterRow = ui->filterTable->rowCount();
    const int column = filterRow + 1;
    {
        const QSignalBlocker blocker(ui->filterTable);
        ui->filterTable->insertRow(filterRow);

        auto *nameItem = new QTableWidgetItem(name);
        nameItem->setCheckState(Qt::Unchecked);
        ui->filterTable->setItem(filterRow, 0, nameItem);

        auto *filterItem = new QTableWidgetItem(filter);
        filterItem->setToolTip(filter);
        ui->filterTable->setItem(filterRow, 1, filterItem);
    }
    {
        const QSignalBlocker blocker(ui->resultsTable);
        ui->resultsTable->insertColumn(column);
        auto *header = new QTableWidgetItem(name);
        header->setToolTip(filter);
        ui->resultsTable->setHorizontalHeaderItem(column, header);

        for (int pcapRow = 0; pcapRow < ui->resultsTable->rowCount(); ++pcapRow)
        {
            auto *cell = new QTableWidgetItem();
            cell->setFlags(cell->flags() & ~Qt::ItemIsEditable);
            cell->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            ui->resultsTable->setItem(pcapRow, column, cell);
        }
    }

    if (!m_loading)
        saveSettings();
}

void MainWindow::on_deleteFilter_clicked()
{
    for (int row : rowsToRemove(ui->filterTable))
    {
        ui->filterTable->removeRow(row);
        ui->resultsTable->removeColumn(row + 1);
    }
    saveSettings();
}

void MainWindow::on_filterTable_cellChanged(int row, int column)
{
    const QTableWidgetItem *item = ui->filterTable->item(row, column);
    if (!item)
        return;

    if (column == 0)
    {
        if (QTableWidgetItem *header = ui->resultsTable->horizontalHeaderItem(row + 1))
            header->setText(item->text());
    }
    else if (column == 1)
    {
        const QSignalBlocker blocker(ui->filterTable);
        ui->filterTable->item(row, 1)->setToolTip(item->text());
        if (QTableWidgetItem *header = ui->resultsTable->horizontalHeaderItem(row + 1))
            header->setToolTip(item->text());

        // The filter changed, so this column's results are stale.
        resetColumn(row);
        if (ui->liveSearch->isChecked())
            searchColumn(row);
    }

    saveSettings();
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

void MainWindow::setTsharkPath(const QString &path)
{
    if (path != m_engine.tsharkPath())
    {
        // Different tshark versions can disagree, so don't reuse old answers.
        m_engine.cancelAll();
        m_engine.clearCache();
        resetPendingCells();
    }
    m_engine.setTsharkPath(path);
    refreshTsharkStatus();
}

void MainWindow::refreshTsharkStatus()
{
    const QString path = m_engine.tsharkPath();
    if (path.isEmpty())
    {
        m_tsharkLabel->setText(tr("tshark not found - install Wireshark or use Settings > Locate tshark"));
        return;
    }

    m_tsharkLabel->setText(tr("tshark: %1").arg(path));
    m_tsharkLabel->setToolTip(path);

    auto *probe = new QProcess(this);
    connect(probe, &QProcess::finished, this, [this, probe, path](int exitCode) {
        const QString firstLine = QString::fromLocal8Bit(probe->readAllStandardOutput()).section('\n', 0, 0).trimmed();
        if (exitCode == 0 && !firstLine.isEmpty() && m_engine.tsharkPath() == path)
            m_tsharkLabel->setText(firstLine);
        probe->deleteLater();
    });
    connect(probe, &QProcess::errorOccurred, this, [this, probe, path](QProcess::ProcessError error) {
        if (error != QProcess::FailedToStart)
            return;
        if (m_engine.tsharkPath() == path)
            m_tsharkLabel->setText(tr("tshark at %1 could not be run").arg(path));
        probe->deleteLater();
    });
    probe->start(path, {QStringLiteral("--version")}, QIODevice::ReadOnly);
}

void MainWindow::on_actionLocateTshark_triggered()
{
    const QString current = m_engine.tsharkPath();
#ifdef Q_OS_WIN
    const QString filter = tr("tshark (tshark.exe);;Programs (*.exe)");
#else
    const QString filter = tr("tshark (tshark);;All files (*)");
#endif
    const QString path = QFileDialog::getOpenFileName(this, tr("Locate tshark"),
                                                      current.isEmpty() ? QString() : QFileInfo(current).absolutePath(),
                                                      filter);
    if (path.isEmpty())
        return;

    if (!TsharkLocator::isUsable(path))
    {
        QMessageBox::warning(this, tr("Not Executable"), tr("%1 is not an executable file.").arg(path));
        return;
    }

    QSettings().setValue(QStringLiteral("tsharkPath"), path);
    setTsharkPath(QDir::toNativeSeparators(path));
}

void MainWindow::on_actionMaxConcurrent_triggered()
{
    bool ok = false;
    const int max = QInputDialog::getInt(this, tr("Parallel Searches"),
                                         tr("Maximum number of tshark processes to run at once:"),
                                         m_engine.maxConcurrent(), 1, 256, 1, &ok);
    if (!ok)
        return;
    m_engine.setMaxConcurrent(max);
    QSettings().setValue(QStringLiteral("maxConcurrent"), max);
}

void MainWindow::on_actionAbout_triggered()
{
    QMessageBox::about(this, tr("About MultiPCAPSearch"),
        tr("<h3>MultiPCAPSearch %1</h3>"
           "<p>Apply several Wireshark display filters to several capture files at once "
           "and compare the matching packet counts side by side.</p>"
           "<p>Uses tshark: <code>%2</code></p>"
           "<p>Built with Qt %3.</p>"
           "<p>Licensed under the GNU Affero General Public License v3.0 or later. "
           "This program comes with ABSOLUTELY NO WARRANTY.</p>"
           "<p><a href=\"https://github.com/sbrown7792/MultiPCAPSearch\">github.com/sbrown7792/MultiPCAPSearch</a></p>")
            .arg(QCoreApplication::applicationVersion(),
                 m_engine.tsharkPath().isEmpty() ? tr("not found") : m_engine.tsharkPath().toHtmlEscaped(),
                 QString::fromLatin1(qVersion())));
}

void MainWindow::loadSettings()
{
    m_loading = true;
    QSettings settings;

    restoreGeometry(settings.value(QStringLiteral("geometry")).toByteArray());
    ui->splitter->restoreState(settings.value(QStringLiteral("splitter")).toByteArray());

    m_engine.setMaxConcurrent(settings.value(QStringLiteral("maxConcurrent"), QThread::idealThreadCount()).toInt());
    setTsharkPath(TsharkLocator::find(settings.value(QStringLiteral("tsharkPath")).toString()));

    const int count = settings.beginReadArray(QStringLiteral("filters"));
    for (int i = 0; i < count; ++i)
    {
        settings.setArrayIndex(i);
        addFilterRow(settings.value(QStringLiteral("name")).toString(),
                     settings.value(QStringLiteral("filter")).toString());
    }
    settings.endArray();

    ui->liveSearch->setChecked(settings.value(QStringLiteral("liveSearch"), false).toBool());
    m_loading = false;
}

void MainWindow::saveSettings() const
{
    if (m_loading)
        return;

    QSettings settings;
    settings.remove(QStringLiteral("filters"));
    settings.beginWriteArray(QStringLiteral("filters"), ui->filterTable->rowCount());
    for (int row = 0; row < ui->filterTable->rowCount(); ++row)
    {
        settings.setArrayIndex(row);
        const QTableWidgetItem *name = ui->filterTable->item(row, 0);
        settings.setValue(QStringLiteral("name"), name ? name->text() : QString());
        settings.setValue(QStringLiteral("filter"), filterText(row));
    }
    settings.endArray();
    settings.setValue(QStringLiteral("liveSearch"), ui->liveSearch->isChecked());
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    QSettings settings;
    settings.setValue(QStringLiteral("geometry"), saveGeometry());
    settings.setValue(QStringLiteral("splitter"), ui->splitter->saveState());
    saveSettings();
    m_engine.cancelAll();
    QMainWindow::closeEvent(event);
}
