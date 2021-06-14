#include "pcap.h"

PCAP::PCAP()
{


}

PCAP::PCAP(QString fileName)
{
    PCAPfile = fileName;
}

PCAP::PCAP(QString fileName, QString name)
{
    PCAPfile = fileName;
    PCAPname = name;
}

bool PCAP::setFile(QString filename)
{
    //test if filename exists/can be opened

    PCAPfile = filename;
    return true;
}


QString PCAP::getName()
{
    return PCAPname;
}

void PCAP::setName(QString name)
{
    PCAPname = name;
}


int PCAP::doSearch(QString PCAPfilter)
{
    //first test if PCAP file is real and openable
    if (false)
    {
        return -1;
    }

    QProcess* m_agent = new QProcess();
    QStringList args = QStringList();
    QString myPath = QDir::currentPath();
    args << myPath + "/tshark.exe -n -r";
    args << PCAPfile;
    args << PCAPfilter;
    args << "| measure-object -line | Select-Object -ExpandProperty Lines";
    m_agent->start("powershell", args);
    m_agent->waitForFinished(30000);

    QString output(m_agent->readAllStandardOutput());
    return output.toInt();
}
