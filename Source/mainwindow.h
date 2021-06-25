#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFileDialog>
#include <QProcess>
#include <QMessageBox>
#include <QInputDialog>

#include "pcap.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:


    void on_addFilter_clicked();

    void on_deleteFilter_clicked();

    void on_liveSearch_stateChanged(int arg1);

    void doSearch();

    void updateResultTable();

    void on_filterTable_cellChanged(int row, int column);

    void on_addPCAP_clicked();

    void on_searchNow_clicked();

    void on_clearResults_clicked();

private:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
