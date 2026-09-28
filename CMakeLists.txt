# SPDX-License-Identifier: AGPL-3.0-or-later
cmake_minimum_required(VERSION 3.19)

project(MultiPCAPSearch
    VERSION 1.0.1
    DESCRIPTION "Count packets matching Wireshark display filters across many capture files"
    HOMEPAGE_URL "https://github.com/sbrown7792/MultiPCAPSearch"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 6.2 REQUIRED COMPONENTS Widgets)
qt_standard_project_setup()

# Everything but main() lives in a static library so the tests can link it too.
qt_add_library(multipcapsearch_core STATIC
    src/mainwindow.cpp
    src/mainwindow.h
    src/mainwindow.ui
    src/searchengine.cpp
    src/searchengine.h
    src/tsharklocator.cpp
    src/tsharklocator.h
)
target_include_directories(multipcapsearch_core PUBLIC src)
target_link_libraries(multipcapsearch_core PUBLIC Qt6::Widgets)

qt_add_executable(MultiPCAPSearch WIN32 MACOSX_BUNDLE
    src/main.cpp
)
target_compile_definitions(MultiPCAPSearch PRIVATE
    MULTIPCAPSEARCH_VERSION="${PROJECT_VERSION}"
)
target_link_libraries(MultiPCAPSearch PRIVATE multipcapsearch_core)

qt_add_resources(MultiPCAPSearch icons
    PREFIX "/"
    BASE packaging/icon
    FILES packaging/icon/MultiPCAPSearch.png)

if(WIN32)
    target_sources(MultiPCAPSearch PRIVATE packaging/windows/MultiPCAPSearch.rc)
elseif(APPLE)
    set_source_files_properties(packaging/macos/MultiPCAPSearch.icns PROPERTIES MACOSX_PACKAGE_LOCATION Resources)
    target_sources(MultiPCAPSearch PRIVATE packaging/macos/MultiPCAPSearch.icns)
    set_target_properties(MultiPCAPSearch PROPERTIES
        MACOSX_BUNDLE_GUI_IDENTIFIER "net.multipcapsearch.MultiPCAPSearch"
        MACOSX_BUNDLE_BUNDLE_NAME "MultiPCAPSearch"
        MACOSX_BUNDLE_ICON_FILE "MultiPCAPSearch.icns"
        MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}")
endif()

include(GNUInstallDirs)
install(TARGETS MultiPCAPSearch
    BUNDLE DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
if(UNIX AND NOT APPLE)
    install(FILES packaging/linux/MultiPCAPSearch.desktop DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
    install(FILES packaging/icon/MultiPCAPSearch.png DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/256x256/apps)
endif()

option(MULTIPCAPSEARCH_BUILD_TESTS "Build the unit tests" ON)
if(MULTIPCAPSEARCH_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
