/*
  This file is part of the Better Inbox project
  Copyright (c) 2011 Better Inbox and/or Gregory Schlomoff.
  All rights reserved.
  contact@betterinbox.com
*/

#ifndef TEST_H
#define TEST_H

#include <QObject>
 #include <QtTest/QtTest>

class Test : public QObject
{
    Q_OBJECT
public:
    explicit Test(QObject *parent = 0);

private slots:
	void oauthSignature_data();
	void oauthSignature();
};

#endif // TEST_H
