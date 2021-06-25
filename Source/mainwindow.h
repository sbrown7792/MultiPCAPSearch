#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFileDialog>
#include <QProcess>
#include <QMessageBox>
#include <QInputDialog>
#include <QtConcurrent>
#include <QMutex>
#include <QTimer>
#include <QTableWidgetItem>


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

    void searchInBG(int, int);

private slots:


    void on_addFilter_clicked();

    void on_deleteFilter_clicked();

    void on_liveSearch_stateChanged(int arg1);

    void doSearch();

    void prepResultTable(QTableWidgetItem* resultItem);
    void updateResultTable(QTableWidgetItem* resultItem, QString stdOut, QString stdErr);

    void on_filterTable_cellChanged(int row, int column);

    void on_addPCAP_clicked();

    void on_searchNow_clicked();

    void on_clearResults_clicked();

    void on_removePCAP_clicked();

private:
    Ui::MainWindow *ui;

signals:
    void newResult(QTableWidgetItem* resultItem, QString stdOut, QString stdErr);
    void startingFilter(QTableWidgetItem* resultItem);

};
#endif // MAINWINDOW_H

Q_DECLARE_METATYPE(PCAP*);
