// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2022-2026 sbrown7792 and MultiPCAPSearch contributors

#ifndef TSHARKLOCATOR_H
#define TSHARKLOCATOR_H

#include <QString>

namespace TsharkLocator
{
    // Finds a tshark executable, trying in order:
    //   1. preferredPath, if it points at an existing executable
    //   2. a tshark shipped next to this application
    //   3. tshark on the PATH
    //   4. the default Wireshark install location for this platform
    // Returns an empty string if none is found.
    QString find(const QString &preferredPath = QString());

    // True if path is an existing, executable file.
    bool isUsable(const QString &path);
}

#endif // TSHARKLOCATOR_H
