#ifndef PCAP_H
#define PCAP_H

#include <QString>
#include <QProcess>
#include <QMessageBox>
#include <QFileDialog>
#include <QHash>


class PCAP
{
public:
    PCAP();

    PCAP(QString fileName);

    PCAP(QString fileName, QString name);

    bool setFile(QString filename);

    void setName(QString name);

    QString doSearch(QString filter);

    void clearResults();

    QString getName();

private:

    QHash<QString, QString> resultHash;

    QString PCAPfile = "";

    QString PCAPname = "";
};

#endif // PCAP_H
