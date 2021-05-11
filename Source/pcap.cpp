#include "pcap.h"

PCAP::PCAP()
{


}

bool PCAP::setFile(QString filename)
{
    //test if filename exists/can be opened

    PCAPfile = filename;
    return true;
}

bool PCAP::setFilter(QString filter)
{
    //filter might need to be tested but for now we'll deal with invalid filters at the "actually filter" phase

    PCAPfilter = filter;
    return true;
}

QString PCAP::getResult()
{
    return PCAPresult;
}


QString PCAP::getFilename()
{
    return PCAPfile;
}

QString PCAP::getFilterString()
{
    return PCAPfilter;
}
