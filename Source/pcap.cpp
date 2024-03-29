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


QString PCAP::doSearch(QString PCAPfilter)
{
    //first test if PCAP file is real and openable
    if (PCAPfile.isEmpty() || PCAPfile.isNull())
    {
        return "Error opening PCAP file";
    }


    //now see if we've already searched for this filter before. if so, just return the already-gotten result
    if (resultHash.contains(PCAPfilter))
    {
        return resultHash.value(PCAPfilter);
    }

    QProcess* m_agent = new QProcess();
    QStringList args = QStringList();
    QString myPath = QDir::currentPath();

    //wrap the path in powershell crap
    args << "& \'" + myPath + "/lib/tshark.exe\' -n -r";

    //wrap the file in quotes
    args << "\"" + PCAPfile + "\"";

    //wrap the filter in quotes
    args << "\"" + PCAPfilter + "\"";

    args << "| measure-object -line | Select-Object -ExpandProperty Lines";
    m_agent->start("powershell", args);
    m_agent->waitForFinished(300000);

    QString output(m_agent->readAllStandardOutput());
    output.append('|');
    output.append(m_agent->readAllStandardError());

    resultHash.insert(PCAPfilter, output);
    return output;
}

void PCAP::clearResults()
{
    resultHash.clear();
}
