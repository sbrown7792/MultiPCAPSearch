// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2022-2026 sbrown7792 and MultiPCAPSearch contributors

#include "mainwindow.h"

#include <QApplication>
#include <QCommandLineParser>
#include <QIcon>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QApplication::setOrganizationName(QStringLiteral("MultiPCAPSearch"));
    QApplication::setApplicationName(QStringLiteral("MultiPCAPSearch"));
    QApplication::setApplicationVersion(QStringLiteral(MULTIPCAPSEARCH_VERSION));
    QApplication::setWindowIcon(QIcon(QStringLiteral(":/MultiPCAPSearch.png")));

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("Count packets matching Wireshark display filters across many capture files."));
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addPositionalArgument(QStringLiteral("files"), QStringLiteral("Capture files to open."), QStringLiteral("[files...]"));
    parser.process(app);

    MainWindow window;
    window.show();
    if (!parser.positionalArguments().isEmpty())
        window.addPcapFiles(parser.positionalArguments(), false);

    return app.exec();
}
