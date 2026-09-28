// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2022-2026 sbrown7792 and MultiPCAPSearch contributors

#ifndef TESTPCAP_H
#define TESTPCAP_H

#include <QByteArray>
#include <QFile>
#include <QString>
#include <QtEndian>

// Writes a classic little-endian pcap of Ethernet/IPv4/UDP packets. Packet i
// (0-based) goes from 10.0.0.<1 + i % srcHosts> to UDP port 53 when
// i % dnsEvery == 0 and to port 8080 otherwise.
inline bool writeTestPcap(const QString &path, int packets, int dnsEvery, int srcHosts = 2)
{
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly))
        return false;

    auto le32 = [](QByteArray &b, quint32 v) { v = qToLittleEndian(v); b.append(reinterpret_cast<const char *>(&v), 4); };
    auto le16 = [](QByteArray &b, quint16 v) { v = qToLittleEndian(v); b.append(reinterpret_cast<const char *>(&v), 2); };
    auto be16 = [](QByteArray &b, quint16 v) { v = qToBigEndian(v); b.append(reinterpret_cast<const char *>(&v), 2); };

    QByteArray out;
    le32(out, 0xa1b2c3d4);  // magic
    le16(out, 2);           // version major
    le16(out, 4);           // version minor
    le32(out, 0);           // thiszone
    le32(out, 0);           // sigfigs
    le32(out, 65535);       // snaplen
    le32(out, 1);           // LINKTYPE_ETHERNET

    const QByteArray payload(16, 'x');
    for (int i = 0; i < packets; ++i)
    {
        QByteArray pkt;
        pkt.append("\x00\x11\x22\x33\x44\x55", 6);   // dst MAC
        pkt.append("\x66\x77\x88\x99\xaa\xbb", 6);   // src MAC
        be16(pkt, 0x0800);                            // IPv4

        const quint16 ipLen = 20 + 8 + payload.size();
        QByteArray ip;
        ip.append(char(0x45));
        ip.append(char(0));
        be16(ip, ipLen);
        be16(ip, quint16(i));
        be16(ip, 0);
        ip.append(char(64));
        ip.append(char(17));                          // UDP
        be16(ip, 0);                                  // checksum, filled below
        ip.append(char(10)); ip.append(char(0)); ip.append(char(0)); ip.append(char(1 + i % srcHosts));
        ip.append(char(10)); ip.append(char(0)); ip.append(char(0)); ip.append(char(100));
        quint32 sum = 0;
        for (int j = 0; j < ip.size(); j += 2)
            sum += (quint8(ip[j]) << 8) | quint8(ip[j + 1]);
        while (sum >> 16)
            sum = (sum & 0xffff) + (sum >> 16);
        const quint16 checksum = quint16(~sum);
        ip[10] = char(checksum >> 8);
        ip[11] = char(checksum & 0xff);
        pkt.append(ip);

        be16(pkt, 40000);                                         // src port
        be16(pkt, (i % dnsEvery == 0) ? 53 : 8080);               // dst port
        be16(pkt, quint16(8 + payload.size()));
        be16(pkt, 0);                                             // no UDP checksum
        pkt.append(payload);

        le32(out, 1700000000 + i);
        le32(out, 0);
        le32(out, pkt.size());
        le32(out, pkt.size());
        out.append(pkt);
    }

    return file.write(out) == out.size();
}

#endif // TESTPCAP_H
