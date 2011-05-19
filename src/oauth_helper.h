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

#ifndef OAUTH_HELPER_H
#define OAUTH_HELPER_H

#include <QObject>
#include <QSslError>

#include "oauth_token.h"
#include "simpleoauth_export.h"

class QNetworkReply;
class QNetworkAccessManager;

namespace OAuth {

class SIMPLEOAUTH_EXPORT Helper : public QObject
{
	Q_OBJECT

public:
	enum OAuthError {
		NoError,
		NetworkError,
		RequestUnauthorized
	};

	explicit Helper(QObject* parent = 0);
	void setOwnNetworkManager(QNetworkAccessManager* networkManager);

	void getRequestToken(Token temporaryToken, QUrl requestUrl);
	void getUserAuthorization(Token requestToken, QUrl authorizationUrl);
	void getAccessToken(Token requestToken, QUrl url);

	OAuthError lastError() const;

signals:
	void requestTokenReceived(OAuth::Token token);
	void accessTokenReceived(OAuth::Token token);

private slots:
	void replyReceived(QNetworkReply* reply);
	void onSslErrors(QNetworkReply* reply, QList<QSslError> errors);

private:
	QNetworkAccessManager* m_networkManager;
	Helper::OAuthError m_error;
	Token m_token;
};
}
#endif // OAUTH_HELPER_H
