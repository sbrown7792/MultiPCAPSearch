#ifndef PCAP_H
#define PCAP_H

#include <QString>
#include <QProcess>
#include <QMessageBox>
#include <QFileDialog>

class PCAP
{
public:
    PCAP();

    PCAP(QString fileName);

    PCAP(QString fileName, QString name);

    bool setFile(QString filename);

    void setName(QString name);

    int doSearch(QString filter);

    QString getName();

private:
    QString PCAPfile = "";

    QString PCAPname = "";
};

#endif // PCAP_H
