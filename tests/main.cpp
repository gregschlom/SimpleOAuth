/*
  This file is part of the Better Inbox project
  Copyright (c) 2011 Better Inbox and/or Gregory Schlomoff.
  All rights reserved.
  contact@betterinbox.com
*/

#include <QCoreApplication>
#include <QDebug>

#include "Test.h"


int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

	Test test;
	test.start();

    return a.exec();
}
