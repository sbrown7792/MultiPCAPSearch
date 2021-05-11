#ifndef PCAP_H
#define PCAP_H

#include <QString>


class PCAP
{
public:
    PCAP();

    bool setFile(QString filename);

    bool setFilter(QString filter);

    bool doSearch();

    QString getResult();

    QString getFilterString();

    QString getFilename();

private:
    QString PCAPfile;
    QString PCAPfilter;
    QString PCAPresult;

};

#endif // PCAP_H
