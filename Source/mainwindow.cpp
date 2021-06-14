#include "mainwindow.h"
#include "ui_mainwindow.h"


QList<PCAP> PCAPList;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    ui->filterTable->setColumnWidth(1,400);
}

MainWindow::~MainWindow()
{
    delete ui;
}



// this command in powershell will filter, count, and tell you how long
//  Measure-command { .\tshark.exe -r ../../Tests/rx.pcap -n "ip.src == 192.168.250.4" | measure-object -line}
//test against speed of filtering to a new file, then running capinfos on that new file

void MainWindow::on_addFilter_clicked()
{
    ui->filterTable->setRowCount(ui->filterTable->rowCount()+1);

    QTableWidgetItem* item = new QTableWidgetItem();
    item->setCheckState(Qt::Unchecked);
    item->setText("Filter" + QString::number(ui->filterTable->rowCount()));

    ui->filterTable->setItem(ui->filterTable->rowCount()-1,0,item);

    item = new QTableWidgetItem();
    ui->filterTable->setItem(ui->filterTable->rowCount()-1,1,item);


    item = new QTableWidgetItem();
    ui->resultsTable->setColumnCount(ui->filterTable->rowCount()+1);
    item->setText(ui->filterTable->item(ui->filterTable->rowCount()-1,0)->text());
    ui->resultsTable->setHorizontalHeaderItem(ui->resultsTable->columnCount()-1,item);

    for (int i=0; i<ui->resultsTable->rowCount(); i++)
    {
        item = new QTableWidgetItem();
        ui->resultsTable->setItem(i,ui->resultsTable->columnCount()-1,item);
    }


}


void MainWindow::on_deleteFilter_clicked()
{
    //iterate through filters and delete the ones the user has checked off

    for (int i=ui->filterTable->rowCount()-1; i>=0; i--)
    {
        if (ui->filterTable->item(i,0)->checkState())
        {
            ui->filterTable->removeRow(i);
            ui->resultsTable->removeColumn(i+1);
        }
    }
}

void MainWindow::on_liveSearch_stateChanged(int arg1)
{
    ui->searchNow->setEnabled(!ui->liveSearch->checkState());
}

void MainWindow::updatePCAPtable()
{



    if (ui->liveSearch->checkState())
    {
        doSearch();
    }
}

void MainWindow::doSearch()
{
    //change this to use filter(s) from list
    //also change to use the PCAP object that will be stored IN the table
    //also i guess, i need to store the PCAP object in the table

    QString myFilters = "ip.src == 192.168.250.4";

    QMessageBox::warning(this, tr("Result"),QString::number(PCAPList[PCAPList.length()-1].doSearch(myFilters)));
}


void MainWindow::on_filterTable_cellChanged(int row, int column)
{
    //make sure we're done allocating items
    if (ui->filterTable->item(row,1) == nullptr)
        return;

    return;
}

void MainWindow::on_addPCAP_clicked()
{
    //prompt user for pcap file
    QString fileName = QFileDialog::getOpenFileName(this,
        tr("Select PCAP"), ".", tr("PCAP Files (*.pcap *.pcapng)"));

    //ask for a friendly name
    QString name = QInputDialog::getText(this, tr("Give this PCAP a name"),
                                             tr("Friendly Name:"), QLineEdit::Normal,
                                             fileName.split("/").last());

    //store the PCAP object in a list - probably need to change it to store in the table, unless we store pointers in the table??
    PCAPList.append(PCAP(fileName,name));

}
