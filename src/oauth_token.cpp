/*
 *  SimpleOauth - A simple OAuth authentication library for Qt
 *
 *  Copyright (C) 2010 Gregory Schlomoff <gregory.schlomoff@gmail.com>
 *                     http://gregschlom.com
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 */

#include "oauth_token_p.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QStringList>
#include <QDebug>

namespace OAuth {

TokenPrivate::TokenPrivate()
	: QSharedData(),
	  tokenType(Token::InvalidToken),
	  consumerKey(),
	  consumerSecret(),
	  callbackUrl(),
	  oauthToken(),
	  oauthTokenSecret(),
	  oauthVerifier()
{
	qsrand(QTime::currentTime().msec());
}

TokenPrivate::TokenPrivate(const TokenPrivate& other)
	: QSharedData(),
	  tokenType(other.tokenType),
	  consumerKey(other.consumerKey),
	  consumerSecret(other.consumerSecret),
	  callbackUrl(other.callbackUrl),
	  oauthToken(other.oauthToken),
	  oauthTokenSecret(other.oauthTokenSecret),
	  oauthVerifier(other.oauthVerifier)
{
	qsrand(QTime::currentTime().msec());
}

Token::Token()
	: d(new TokenPrivate())
{
}

Token::~Token()
{
}

Token::Token(const Token& other)
	: d(other.d)
{
}

Token& Token::operator=(const Token& other)
{
	if (this != &other) {
		d = other.d;
	}
	return *this;
}

// Helper function to avoid writting "QString(QUrl::toPercentEncoding(xxx)" 10 times
inline QString encode(QString string) { return QString(QUrl::toPercentEncoding(string)); }

QByteArray Token::signRequest(const QUrl& requestUrl, Token::AuthMethod authMethod, Token::HttpMethod method, const QMultiMap<QString, QString>& parameters) const
{
	QString timestamp;
	QString nonce;

	if (d->consumerKey == "test_token") { // Set known values for unit-testing
		timestamp = "1234567890";	//Feb 13, 2009, 23:31:30 GMT
		nonce = "ABCDEF";
	} else {
		timestamp = QString::number(QDateTime::currentDateTimeUtc().toTime_t());
		nonce = QString::number(qrand());
	}

	if (!requestUrl.isValid()) {
		qWarning() << "OAuth::Token: Invalid url. The request will probably be invalid";
	}

	// Step 1. Get all the oauth params for this request

	QMultiMap<QString, QString> oauthParams;

	oauthParams.insert("oauth_consumer_key", d->consumerKey);
	oauthParams.insert("oauth_signature_method", "HMAC-SHA1");
	oauthParams.insert("oauth_timestamp", timestamp);
	oauthParams.insert("oauth_nonce", nonce);
	oauthParams.insert("oauth_version", "1.0");

	switch (d->tokenType) {
	case Token::InvalidToken:
		oauthParams.insert("oauth_callback", d->callbackUrl.toString());
		break;

	case Token::RequestToken:
		oauthParams.insert("oauth_token", d->oauthToken);
		oauthParams.insert("oauth_verifier", d->oauthVerifier);
		break;

	case Token::AccessToken:
		oauthParams.insert("oauth_token", d->oauthToken);
		break;
	}

	// Step 2. Take the parameters from the url, and add the oauth params to them

	QMultiMap<QString, QString> allParams = oauthParams;
	QList<QPair<QString, QString> > queryItems = requestUrl.queryItems();
	for(int i = 0; i < queryItems.count(); ++i) {
		allParams.insert(queryItems[i].first, queryItems[i].second);
	}

	allParams.unite(parameters);

	// Step 3. Calculate the signature from those params, and append the signature to the oauth params

	QString signature = generateSignature(requestUrl, allParams, method);
	oauthParams.insert("oauth_signature", signature);

	// Step 4. Concatenate all oauth params into one comma-separated string

	QByteArray authHeader;

	if (authMethod == Sasl) {
		authHeader = "GET ";
		authHeader.append(requestUrl.toString() + " ");
	} else {
		authHeader = "OAuth ";
	}

	QMultiMap<QString, QString>::const_iterator p = oauthParams.constBegin();
	while (p != oauthParams.constEnd()) {
		authHeader += QString("%1=\"%2\",").arg(p.key()).arg(encode(p.value()));
		++p;
	}
	authHeader.chop(1); // remove the last character (the trailing ",")

	return authHeader;
}

/*!
  \internal
  Generates the OAuth signature.
  \see http://oauth.net/core/1.0a/#signing_process
*/
QString Token::generateSignature(const QUrl& requestUrl, const QMultiMap<QString, QString>& requestParameters, HttpMethod method) const
{
	QString key = encode(d->consumerSecret) + "&" + encode(d->oauthTokenSecret);
	QString baseString;

	switch (method) {
	case HttpGet:    baseString = "GET&";    break;
	case HttpPost:   baseString = "POST&";   break;
	case HttpPut:    baseString = "PUT&";    break;
	case HttpDelete: baseString = "DELETE&"; break;
	case HttpHead:   baseString = "HEAD&";   break;
	}

	baseString += encode(requestUrl.toString(QUrl::RemoveQuery)) + "&";

	// encode and concatenate the parameters into a string
	QStringList params;
	QMap<QString, QString>::const_iterator p = requestParameters.constBegin();
	while (p != requestParameters.constEnd()) {
		params << QString("%1=%2").arg(encode(p.key())).arg(encode(p.value()));
		++p;
	}
	qSort(params);

	baseString += encode(params.join("&"));

	// Ok, we have the normalized base string and the key, calculate the HMAC-SHA1 signature
	return hmac_sha1(baseString, key);
}

/*!
  Calculates the HMAC-SHA1 signature from a message and a key.
  This method comes from the kQOAuth library (http://www.d-pointer.com/solutions/kqoauth/)
  Author: Johan Paul (johan.paul@d-pointer.com)
*/
QString Token::hmac_sha1(const QString& message, const QString& key) const
{
	QByteArray keyBytes = key.toAscii();
	int keyLength;              // Length of key word
	const int blockSize = 64;   // Both MD5 and SHA-1 have a block size of 64.

	keyLength = keyBytes.size();
	// If key is longer than block size, we need to hash the key
	if (keyLength > blockSize) {
		QCryptographicHash hash(QCryptographicHash::Sha1);
		hash.addData(keyBytes);
		keyBytes = hash.result();
	}

	/* http://tools.ietf.org/html/rfc2104  - (1) */
	// Create the opad and ipad for the hash function.
	QByteArray ipad;
	QByteArray opad;

	ipad.fill( 0, blockSize);
	opad.fill( 0, blockSize);

	ipad.replace(0, keyBytes.length(), keyBytes);
	opad.replace(0, keyBytes.length(), keyBytes);

	/* http://tools.ietf.org/html/rfc2104 - (2) & (5) */
	for (int i=0; i<64; i++) {
		ipad[i] = ipad[i] ^ 0x36;
		opad[i] = opad[i] ^ 0x5c;
	}

	QByteArray workArray;
	workArray.clear();

	workArray.append(ipad, 64);
	/* http://tools.ietf.org/html/rfc2104 - (3) */
	workArray.append(message.toAscii());


	/* http://tools.ietf.org/html/rfc2104 - (4) */
	QByteArray sha1 = QCryptographicHash::hash(workArray, QCryptographicHash::Sha1);

	/* http://tools.ietf.org/html/rfc2104 - (6) */
	workArray.clear();
	workArray.append(opad, 64);
	workArray.append(sha1);

	sha1.clear();

	/* http://tools.ietf.org/html/rfc2104 - (7) */
	sha1 = QCryptographicHash::hash(workArray, QCryptographicHash::Sha1);
	return QString(sha1.toBase64());
}

// Setters
void Token::setType          (Token::TokenType type)            { d->tokenType = type; }
void Token::setConsumerKey   (const QString& consumerKey)       { d->consumerKey = consumerKey; }
void Token::setConsumerSecret(const QString& consumerSecretKey) { d->consumerSecret = consumerSecretKey; }
void Token::setTokenString   (const QString& token)             { d->oauthToken = token; }
void Token::setTokenSecret   (const QString& tokenSecret)       { d->oauthTokenSecret = tokenSecret; }
void Token::setVerifier      (const QString& verifier)          { d->oauthVerifier = QUrl::fromPercentEncoding(verifier.toAscii()); }
void Token::setCallbackUrl   (const QUrl& callbackUrl)          { d->callbackUrl = callbackUrl; }

// Getters
Token::TokenType Token::type()        const { return d->tokenType; }
QString          Token::tokenString() const { return d->oauthToken; }
QString          Token::tokenSecret() const { return d->oauthTokenSecret; }
}