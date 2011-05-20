/*
  This file is part of the Better Inbox project
  Copyright (c) 2011 Better Inbox and/or Gregory Schlomoff.
  All rights reserved.
  contact@betterinbox.com
*/

#include "Test.h"
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QDebug>
#include <QUrl>
#include <QMultiMap>

#include "oauth_token.h"

typedef QMultiMap<QString, QString> StringMap;
Q_DECLARE_METATYPE(StringMap)
Q_DECLARE_METATYPE(OAuth::Token::HttpMethod)

Test::Test(QObject *parent) :
    QObject(parent)
{
}

/*!
  Expected signatures generated from:
  http://hueniverse.com/2008/10/beginners-guide-to-oauth-part-iv-signing-requests/
*/
void Test::oauthSignature_data()
{
	qRegisterMetaType<OAuth::Token::HttpMethod>();
	qRegisterMetaType<StringMap>();

	QTest::addColumn<QUrl>("url");
	QTest::addColumn<OAuth::Token::HttpMethod>("method");
	QTest::addColumn<StringMap>("params");
	QTest::addColumn<QString>("expectedSignature");

	StringMap params;

	QTest::newRow("simple url") << QUrl("http://example.com/path?param1=123&param2=345") << OAuth::Token::HttpGet << params << "lT%2F9sWSyfbt%2Fc%2BfoqYAHjtrlHWw%3D";
	QTest::newRow("params repeated") << QUrl("http://example.com/path?param=123&param=345")<< OAuth::Token::HttpGet << params << "BuWBw8WGvgqWJXbskF6XIkVy5v4%3D" ;
	QTest::newRow("https+unusual port") << QUrl("https://example.com:120/path?param1=123&param2=345") << OAuth::Token::HttpGet << params << "b%2F2CBx4jQuV4eoXMgaHFue%2F8CoY%3D";

	params.clear();
	params.insert("param1", "123");
	params.insert("param2", "345");
	QTest::newRow("POST") << QUrl("http://example.com/path") << OAuth::Token::HttpPost << params << "KgEjaHO%2Bs%2FNPQ7HMlVp7AdBYRUw%3D";
}


void Test::oauthSignature()
{
    QFETCH( QUrl, url );
	QFETCH( OAuth::Token::HttpMethod, method );
	QFETCH( StringMap, params );
	QFETCH( QString, expectedSignature );

	OAuth::Token token;
	token.setType(OAuth::Token::AccessToken);
    token.setConsumerKey("test_token");	// forces nonce to ABCDEF and timestamp to 1234567890 (Feb 13, 2009, 23:31:30 GMT)
	token.setConsumerSecret("consumersecret");
	token.setTokenString("tokenstring");
	token.setTokenSecret("tokensecret");

	QString authHeader = QString(token.signRequest(url, OAuth::Token::Sasl, method, params));
	QRegExp regExp("oauth_signature=\"([^\"]*)");	// Extract the signature out of the Auth header
	regExp.indexIn(authHeader);
	QString signature = regExp.cap(1);

	QCOMPARE(QString(signature), expectedSignature);

}

QTEST_MAIN(Test)