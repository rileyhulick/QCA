TEMPLATE = app
TARGET = loggerunittest
DEPENDPATH += .
include(../unittest.pri)
CONFIG += qtestlib thread console
QT -= gui

# check target
QMAKE_EXTRA_TARGETS = check
check.depends = loggerunittest
check.commands = ./loggerunittest

# Input
SOURCES += loggerunittest.cpp
