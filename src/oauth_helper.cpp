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

#include "oauth_helper.h"

#include <QDesktopServices>
#include <QNetworkReply>
#include <QStringList>

namespace OAuth {

Helper::Helper(QObject* parent)
	: QObject(parent),
	  m_error(Helper::NoError),
	  m_networkManager(new QNetworkAccessManager(this)),
	  m_token()
{
	connect(m_networkManager, SIGNAL(finished(QNetworkReply*)), SLOT(replyReceived(QNetworkReply*)));
	connect(m_networkManager, SIGNAL(sslErrors(QNetworkReply*,QList<QSslError>)), SLOT(onSslErrors(QNetworkReply*,QList<QSslError>)));
}

/*!
  Sets your own QNetworkAccessManager instance to use.
  This is useful if you have proxy settings, for example.
*/
void Helper::setOwnNetworkManager(QNetworkAccessManager* networkManager)
{
	m_networkManager = networkManager;
}

/*!
  Requires: valid consumerKey, consumerSecret and CallBackUrl
*/
void Helper::getRequestToken(Token temporaryToken, QUrl requestUrl)
{
	m_token = temporaryToken;
	m_token.setType(Token::InvalidToken);

	QNetworkRequest request;
	request.setUrl(requestUrl);
	request.setRawHeader("Authorization", m_token.signRequest(request.url()));
	m_networkManager->get(request);
}

/*!
  Requires: tokenType == Token::RequestToken, and valid oauth_token
*/
void Helper::getUserAuthorization(Token requestToken, QUrl authorizationUrl)
{
	authorizationUrl.addEncodedQueryItem("oauth_token", requestToken.tokenString().toAscii());
	QDesktopServices::openUrl(authorizationUrl);
}

/*!
  Requires: tokenType == Token::RequestToken, and valid oauth_token and verifier
*/
void Helper::getAccessToken(Token requestToken, QUrl url)
{
	m_token = requestToken;
	m_token.setType(Token::RequestToken);

	QNetworkRequest request;
	request.setUrl(url);
	request.setRawHeader("Authorization", m_token.signRequest(request.url()));
	m_networkManager->get(request);
}

void Helper::replyReceived(QNetworkReply* reply)
{
	switch (reply->error()) {
	case QNetworkReply::NoError:
		m_error = Helper::NoError;
		break;

	case QNetworkReply::ContentAccessDenied:
	case QNetworkReply::ContentOperationNotPermittedError:
	case QNetworkReply::ContentNotFoundError:
	case QNetworkReply::AuthenticationRequiredError:
	case QNetworkReply::UnknownContentError:
	case QNetworkReply::ProtocolFailure:
		m_error = Helper::RequestUnauthorized;
		break;

	default:
		m_error = Helper::NetworkError;
		break;
	}

	QByteArray replyString = reply->readAll();

	QMap<QString, QString> response;
	QStringList parameterPairs = QString(replyString).split('&', QString::SkipEmptyParts);
	foreach (const QString& pair, parameterPairs) {
		QStringList p = pair.split('=');
		if (p.count() == 2) {
			response.insert(p[0], QUrl::fromPercentEncoding(p[1].toAscii()));
		}
	}

	if (m_error == Helper::NoError
			&& (response["oauth_token"].isEmpty() || response["oauth_token_secret"].isEmpty())) {
		m_error = Helper::RequestUnauthorized;
	}

	m_token.setTokenString(response["oauth_token"]);
	m_token.setTokenSecret(response["oauth_token_secret"]);

	switch (m_token.type()) {
	case Token::InvalidToken:
		if (m_error == Helper::NoError) {
			m_token.setType(Token::RequestToken);
		}
		emit requestTokenReceived(m_token);
		break;

	case Token::RequestToken:
		if (m_error == Helper::NoError) {
			m_token.setType(Token::AccessToken);
		}
		emit accessTokenReceived(m_token);
		break;
	case Token::AccessToken: //To avoid warning on Mac OSX
		break;
	}

	reply->deleteLater();
}

void Helper::onSslErrors(QNetworkReply* reply, QList<QSslError> errors)
{
	Q_UNUSED(errors);
	reply->ignoreSslErrors();
}

Helper::OAuthError Helper::lastError() const { return m_error; }
}
