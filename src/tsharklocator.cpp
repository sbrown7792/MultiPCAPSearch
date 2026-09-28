// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2022-2026 sbrown7792 and MultiPCAPSearch contributors

#include "tsharklocator.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QStandardPaths>
#include <QStringList>

namespace
{
#ifdef Q_OS_WIN
    const QString exeName = QStringLiteral("tshark.exe");
#else
    const QString exeName = QStringLiteral("tshark");
#endif

    QStringList platformDefaults()
    {
        QStringList paths;
#if defined(Q_OS_WIN)
        for (const char *var : {"ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"})
        {
            const QString dir = qEnvironmentVariable(var);
            if (!dir.isEmpty())
                paths << QDir(dir).filePath(QStringLiteral("Wireshark/tshark.exe"));
        }
        paths << QStringLiteral("C:/Program Files/Wireshark/tshark.exe");
#elif defined(Q_OS_MACOS)
        paths << QStringLiteral("/Applications/Wireshark.app/Contents/MacOS/tshark")
              << QDir::home().filePath(QStringLiteral("Applications/Wireshark.app/Contents/MacOS/tshark"))
              << QStringLiteral("/opt/homebrew/bin/tshark")
              << QStringLiteral("/usr/local/bin/tshark");
#else
        paths << QStringLiteral("/usr/bin/tshark")
              << QStringLiteral("/usr/local/bin/tshark")
              << QStringLiteral("/usr/sbin/tshark");
#endif
        return paths;
    }
}

bool TsharkLocator::isUsable(const QString &path)
{
    if (path.isEmpty())
        return false;
    const QFileInfo info(path);
    return info.isFile() && info.isExecutable();
}

QString TsharkLocator::find(const QString &preferredPath)
{
    if (isUsable(preferredPath))
        return QDir::toNativeSeparators(QFileInfo(preferredPath).absoluteFilePath());

    const QDir appDir(QCoreApplication::applicationDirPath());
    for (const QString &candidate : {appDir.filePath(exeName),
                                     appDir.filePath(QStringLiteral("tshark/") + exeName)})
    {
        if (isUsable(candidate))
            return QDir::toNativeSeparators(candidate);
    }

    const QString onPath = QStandardPaths::findExecutable(QStringLiteral("tshark"));
    if (!onPath.isEmpty())
        return QDir::toNativeSeparators(onPath);

    for (const QString &candidate : platformDefaults())
    {
        if (isUsable(candidate))
            return QDir::toNativeSeparators(candidate);
    }

    return QString();
}
