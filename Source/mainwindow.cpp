#include "mainwindow.h"
#include "ui_mainwindow.h"


QList<PCAP> PCAPList;
bool addingRow=false;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    ui->filterTable->setColumnWidth(1,400);
    ui->filterTable->horizontalHeader()->setStretchLastSection(true);

}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::on_addFilter_clicked()
{
    addingRow=true;
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

    //fill in the blank row items for the new column in the results table
    //start from the first row 0 and go for all the PCAPs, adding new item in the same column for each row
    for (int i=0; i<ui->resultsTable->rowCount(); i++)
    {
        item = new QTableWidgetItem();
        ui->resultsTable->setItem(i,ui->resultsTable->columnCount()-1,item);
    }
    addingRow=false;
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

    if (ui->liveSearch->checkState())
    {
        doSearch();
    }
}

void MainWindow::updateResultTable(QTableWidgetItem* resultItem, QString stdOut, QString stdErr)
{
    resultItem->setText(stdOut);
    resultItem->setToolTip(stdErr);

    if (!(stdErr.isNull() || stdErr.isEmpty()))
    {
        //highlight the cell because there's an error
        resultItem->setBackground(QColor("red"));
    }
}

void MainWindow::prepResultTable(QTableWidgetItem *resultItem)
{
    resultItem->setBackground(QColor("white"));
    resultItem->setText("Filtering...");
    resultItem->setToolTip("May take up to 5 minutes");
}

void MainWindow::searchInBG(int i, int j)
{
    QTableWidgetItem* resultItem = ui->resultsTable->item(i,j+1);

    emit startingFilter(resultItem);

    QString filter = ui->filterTable->item(j,1)->text();

    PCAP *searchPCAP = ui->resultsTable->item(i,0)->data(Qt::UserRole).value<PCAP*>();
    QString result = searchPCAP->doSearch(filter);
    QString stdOut = result.split('|').at(0).split('\n').at(0);
    QString stdErr = result.split('|').at(1);

    emit newResult(resultItem,stdOut,stdErr);
}

void MainWindow::doSearch()
{
    //connect signals to slots so the main thread will do the update on the gui, not the searchInBG thread
    connect(this,SIGNAL(newResult(QTableWidgetItem*,QString,QString)),SLOT(updateResultTable(QTableWidgetItem*,QString,QString)));
    connect(this,SIGNAL(startingFilter(QTableWidgetItem*)),SLOT(prepResultTable(QTableWidgetItem*)));

    //iterate through PCAP rows
    for (int i=0;i<ui->resultsTable->rowCount();i++)
    {
        //iterate through filter rows
        for (int j=0;j<ui->filterTable->rowCount();j++)
        {
            QtConcurrent::run(this, &MainWindow::searchInBG, i, j);
        }
    }
}


void MainWindow::on_filterTable_cellChanged(int row, int column)
{
    //make sure we're done allocating items
    if (ui->filterTable->item(row,0) == nullptr)
        return;
    if (ui->filterTable->item(row,1) == nullptr)
        return;
    if (addingRow)
        return;

    //else, figure out what updated
    //is is the filter name?
    if (column == 0)
    {
        //set the header to the text from the filter table
        ui->resultsTable->horizontalHeaderItem(row+1)->setText(ui->filterTable->item(row,column)->text());
        return;
    }
    //or is it the filter text itself?
    if (column == 1)
    {
        //make the tooltip the text so maybe not have to scroll?
        ui->filterTable->item(row,column)->setToolTip(ui->filterTable->item(row,column)->text());

        //clear out the result text from everything in this column, since the filter text changed.
        for (int i=0;i<ui->resultsTable->rowCount();i++)
        {
            ui->resultsTable->item(i,row+1)->setText("");
            ui->resultsTable->item(i,row+1)->setBackground(QColor("white"));
        }
        //check if live search is turned on and if so, re-run search(es)
        if (ui->liveSearch->checkState())
        {
            doSearch();
        }
    }
    return;
}

void MainWindow::on_addPCAP_clicked()
{

    //prompt user for pcap file
    QString fileName = QFileDialog::getOpenFileName(this, tr("Select PCAP"), ".", tr("PCAP Files (*.pcap *.pcapng)"));

    if (fileName.isEmpty() || fileName.isNull())
    {
        return;
    }

    //ask for a friendly name
    QString name = QInputDialog::getText(this, tr("Give this PCAP a name"), tr("Friendly Name:"), QLineEdit::Normal,fileName.split("/").last().split(".pcap").at(0));
    if (name.isEmpty() || name.isNull())
    {
        name = fileName;
    }

    //store the PCAP object in a list - probably need to change it to store in the table, unless we store pointers in the table??
    //PCAPList.append(PCAP(fileName,name));

    addingRow=true;
    ui->resultsTable->setRowCount(ui->resultsTable->rowCount()+1);

    QTableWidgetItem *pcapFile = new QTableWidgetItem();
    PCAP* temp = new PCAP(fileName,name);
    pcapFile->setData(Qt::UserRole,QVariant::fromValue<PCAP*>(temp));
    pcapFile->setCheckState(Qt::Unchecked);

    int row = ui->resultsTable->rowCount()-1;
    ui->resultsTable->setItem(row,0,pcapFile);
    ui->resultsTable->item(row,0)->setText(name);
    ui->resultsTable->item(row,0)->setToolTip(fileName);

    //fill in the blank column items for new row in the results table
    //column 0 is the name of the PCAP, we must make new items (and insert) for columns 1 - n (where n is number of filters)
    for (int i=0; i<ui->filterTable->rowCount(); i++)
    {
        QTableWidgetItem *item = new QTableWidgetItem();
        ui->resultsTable->setItem(ui->resultsTable->rowCount()-1,i+1,item);
    }
    addingRow=false;

    //check if live search is turned on and if so, re-run search(es)
    if (ui->liveSearch->checkState())
    {
        doSearch();
    }

}

void MainWindow::on_searchNow_clicked()
{
    doSearch();
}

void MainWindow::on_clearResults_clicked()
{
    //iterate through PCAP rows
    for (int i=0;i<ui->resultsTable->rowCount();i++)
    {
        PCAP *searchPCAP = ui->resultsTable->item(i,0)->data(Qt::UserRole).value<PCAP*>();
        searchPCAP->clearResults();
        //iterate through filter rows
        for (int j=0;j<ui->filterTable->rowCount();j++)
        {
            ui->resultsTable->item(i,j+1)->setText("");
            ui->resultsTable->item(i,j+1)->setToolTip("");
            ui->resultsTable->item(i,j+1)->setBackground(QColor("white"));
        }
    }
}

void MainWindow::on_removePCAP_clicked()
{
    for (int i=ui->resultsTable->rowCount();i>0;i--)
    {
        if (ui->resultsTable->item(i-1,0)->checkState())
        {
            ui->resultsTable->removeRow(i-1);
        }
    }
}
