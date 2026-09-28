// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2022-2026 sbrown7792 and MultiPCAPSearch contributors

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include "searchengine.h"

class QLabel;
class QTableWidget;
class QTableWidgetItem;

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

    // Adds capture files as new rows. If askForName is set, prompts for a
    // friendly name for each one; otherwise the file's base name is used.
    void addPcapFiles(const QStringList &files, bool askForName);

    // Adds a filter row (and matching results column).
    void addFilterRow(const QString &name, const QString &filter);

protected:
    void closeEvent(QCloseEvent *event) override;
    void dragEnterEvent(QDragEnterEvent *event) override;
    void dropEvent(QDropEvent *event) override;

private slots:
    void on_addPCAP_clicked();
    void on_removePCAP_clicked();
    void on_clearResults_clicked();
    void on_exportCsv_clicked();

    void on_addFilter_clicked();
    void on_deleteFilter_clicked();
    void on_filterTable_cellChanged(int row, int column);

    void on_liveSearch_toggled(bool checked);
    void on_searchNow_clicked();
    void on_stopSearch_clicked();

    void on_actionLocateTshark_triggered();
    void on_actionMaxConcurrent_triggered();
    void on_actionAbout_triggered();

    void onSearchStarted(const QString &file, const QString &filter);
    void onResultReady(const QString &file, const QString &filter, const SearchResult &result);
    void onPendingJobsChanged(int pending);

private:
    enum CellState { Idle, Queued, Running, Done };

    QString pcapFile(int pcapRow) const;
    QString filterText(int filterRow) const;
    QTableWidgetItem *resultCell(int pcapRow, int filterRow) const;

    void searchAll();
    void searchColumn(int filterRow);
    void searchRow(int pcapRow);
    void searchCell(int pcapRow, int filterRow);

    void resetCell(QTableWidgetItem *cell);
    void resetColumn(int filterRow);
    void resetPendingCells();
    void setCellResult(QTableWidgetItem *cell, const SearchResult &result);
    template <typename Fn> void forEachMatchingCell(const QString &file, const QString &filter, Fn fn);

    // Rows the user ticked or, if none are ticked, the selected rows. Descending order.
    static QList<int> rowsToRemove(QTableWidget *table);

    void setTsharkPath(const QString &path);
    void refreshTsharkStatus();
    void loadSettings();
    void saveSettings() const;

    Ui::MainWindow *ui;
    SearchEngine m_engine;
    QLabel *m_tsharkLabel;
    bool m_loading = false;
};

#endif // MAINWINDOW_H
