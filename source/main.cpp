/**
 *  @brief example code for liboauth using http://term.ie/oauth/example
 *  @file oauthexample.c
 *  @author Robin Gareus <robin@gareus.org>
 *
 * Copyright 2008 Robin Gareus <robin@gareus.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctime>
#include <Windows.h>
#include <windows.h>
#include <shlwapi.h>
#include "oauth.h"

#include "picojson.h"

#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <cstdio>

#include <shlobj.h>

#include "../include/curl/curl.h"

#pragma comment( lib, "shlwapi.lib" )
#pragma comment( lib, "kernel32.lib" )
#pragma comment( lib, "user32.lib" )

/**
 * split and parse URL parameters replied by the test-server
 * into <em>oauth_token</em> and <em>oauth_token_secret</em>.
 */
bool parse_reply(const char *reply, std::string *token, std::string *secret)
{
	std::vector<std::string> arr;

	char const *end = reply + strlen(reply);
	char const *left = reply;
	char const *right = left;
	while (1) {
		int c = 0;
		if (right < end) {
			c = *right;
		}
		if (c == 0 || c == '&') {
			std::string str(left, right);
			arr.push_back(str);
			if (c == 0) {
				break;
			}
			right++;
			left = right;
		}
		right++;
	}

	char const *oauth_token = 0;
	char const *oauth_token_secret = 0;

	for (std::vector<std::string>::const_iterator it = arr.begin(); it != arr.end(); it++) {
		if (strncmp(it->c_str(), "oauth_token=", 12) == 0) {
			oauth_token = it->c_str() + 12;
		} else if (strncmp(it->c_str(), "oauth_token_secret=", 19) == 0) {
			oauth_token_secret = it->c_str() + 19;
		}
	}

	if (oauth_token && oauth_token_secret) {
		if (token) {
			*token = oauth_token;
		}
		if (secret) {
			*secret = oauth_token_secret;
		}
		return true;
	}

	return false;
}

#include <stdio.h>

std::string inputtext()
{
	char tmp[100];
	fgets(tmp, 100, stdin);
	size_t i = strlen(tmp);
	while (i > 0 && (tmp[i - 1] == '\n' || tmp[i - 1] == '\r')) {
		i--;
	}
	return std::string(tmp, tmp + i);
}

/**
 * 文字列中から文字列を検索して別の文字列に置換する
 * @param str  : 置換対象の文字列。上書かれます。
 * @param from : 検索文字列
 * @param to   : 置換後の文字列
 */
void strReplace (std::string& str, const std::string& from, const std::string& to) {
    std::string::size_type pos = 0;
    while(pos = str.find(from, pos), pos != std::string::npos) {
        str.replace(pos, from.length(), to);
        pos += to.length();
    }
}

BOOL GetCUIAppMsg( LPSTR cmdline, LPSTR buf, DWORD size, BOOL gstdout, BOOL gstderr, DWORD timeout )
{
	HANDLE				read,	write;
 	SECURITY_ATTRIBUTES	sa;
	STARTUPINFO 		si;
	PROCESS_INFORMATION	pi;
	DWORD				len;
	BOOL 				isOK = FALSE;

	sa.nLength				=	sizeof(sa);
	sa.lpSecurityDescriptor	=	0;
	sa.bInheritHandle		=	TRUE;

	if( !CreatePipe( &read, &write, &sa, 0 ) ) {

		return FALSE;
	}

	memset( &si, 0, sizeof(si) );
	si.cb			=	sizeof(si);
	si.dwFlags		=	STARTF_USESTDHANDLES;
	si.wShowWindow	= 	SW_HIDE;
	if( gstdout ) si.hStdOutput	=	write;
	if( gstderr ) si.hStdError	=	write;

	do
	{
		if( !CreateProcess( NULL, cmdline, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi ) ) break;
		/*if( WaitForInputIdle( pi.hProcess, timeout ) == -1 ) {
			LPVOID lpMsgBuf;

			FormatMessage(

				FORMAT_MESSAGE_ALLOCATE_BUFFER |

				FORMAT_MESSAGE_FROM_SYSTEM |

				FORMAT_MESSAGE_IGNORE_INSERTS,

				NULL,

				GetLastError(),

				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // 既定の言語

				(LPTSTR) &lpMsgBuf,

				0,

				NULL

			);

			MessageBox(NULL, (LPCTSTR)lpMsgBuf, "Error", MB_OK | MB_ICONINFORMATION);

			LocalFree(lpMsgBuf);

			break;
		}*/
		if( WaitForSingleObject( pi.hProcess, timeout ) != WAIT_OBJECT_0 ) break;

		CloseHandle( pi.hThread );
		CloseHandle( pi.hProcess );

		if( !PeekNamedPipe( read, NULL, 0, NULL, &len, NULL ) ) break;

		memset( buf, '\0', size );

		if( len > 0 && !ReadFile( read, buf, size - 1, &len, NULL ) ) break;

		isOK = TRUE;
	}
	while(0);

	CloseHandle( read );
	CloseHandle( write );

	return isOK;
}

//static char const consumer_key[] = "xxxxxxxxxxxxxxxxxxxxxx";
//static char const consumer_secret[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
#include "../auth.txt" // ←このファイルは秘密です。↑の様な内容が書かれただけのファイルです。

using namespace picojson;

#include "socket.h"

void twitter_example()
{
	static const char *request_token_uri = "http://api.twitter.com/oauth/request_token";
	static const char *authorize_uri = "http://api.twitter.com/oauth/authorize";
	static const char *access_token_uri = "http://api.twitter.com/oauth/access_token";

	std::string c_key; //< consumer key
	std::string c_secret; //< consumer secret

	std::string t_key;
	std::string t_secret;

	std::string req_url;
	std::string postarg;
	std::string reply;
	std::string reply2;
	std::string preply;

	long long int since_id=0;

#if 0

	//

	c_key = consumer_key;
	c_secret = consumer_secret;

	//

	printf("Request token..\n");
	
	{
		std::string reply;
		std::string req_url = oauth_sign_url2(request_token_uri, &postarg, OA_HMAC, 0, c_key.c_str(), c_secret.c_str(), 0, 0);
		reply = oauth_http_post(req_url.c_str(),postarg.c_str(), false);

		if (!parse_reply(reply.c_str(), &t_key, &t_secret)) {
			throw "failed to get request token.";
		}
	}

	//

	printf("Authorize..\n");

	{
		std::string req_url = oauth_sign_url2(authorize_uri, 0, OA_HMAC, 0, c_key.c_str(), c_secret.c_str(), t_key.c_str(), t_secret.c_str());

		printf("Opening...\n");
		puts(req_url.c_str());

		ShellExecute(0, 0, req_url.c_str(), 0, 0, SW_SHOW); // ウェブブラウザを起動する
	}

	//

	{
		printf("Input PIN: ");
		std::string pin = inputtext();
		putchar('\n');

		printf("Access token..\n");

		std::string url = access_token_uri;
		url += "?oauth_verifier=";
		url += pin;

		std::string req_url = oauth_sign_url2(url.c_str(), 0, OA_HMAC, 0, c_key.c_str(), 0, t_key.c_str(), 0);
		std::string reply = oauth_http_get(req_url.c_str(), postarg.c_str());

		if (!parse_reply(reply.c_str(), &t_key, &t_secret)) {
			throw "failed to get access token.";
		}
	}

	// now retrieved 't_key' is access token and 't_secret' is access secret.

	printf("access key: %s\n", t_key.c_str());
	printf("access secret: %s\n", t_secret.c_str());
#else
	c_key = consumer_key;
	c_secret = consumer_secret;
    t_key = access_key;
    t_secret = access_secret;
#endif
	// call Twitter API

	printf("make some request..\n");

	char filename[256] = "screen.txt";
	char screen[100][20];
	time_t local_t;
	struct tm *local_st;
	FILE *tlf,*wlf,*dlf;
	value v;
	std::string uri;

	tlf=fopen("screen.txt","r");

	while (!feof(tlf)) {
		int i;
		
		for (i=0;i<100 && !feof(tlf);i++) {
			fgets(screen[i],20,tlf);
			if (screen[i][strlen(screen[i])-1]=='\n') screen[i][strlen(screen[i])-1]='\0';
		}

		uri = "http://api.twitter.com/1.1/users/lookup.json?user_id=1279762976";
		
		printf("Request URL: %s\n",uri.c_str());
		printf("making request...");

		req_url = oauth_sign_url2(uri.c_str(), 0, OA_HMAC, 0, c_key.c_str(), c_secret.c_str(), t_key.c_str(), t_secret.c_str());
		reply = oauth_http_get(req_url.c_str(), postarg.c_str());
		
		printf("completed\n");

		if (reply.size()==0) {
			printf("Error. ");
			printf("Checking API status...");
			uri = "http://api.twitter.com/account/rate_limit_status.json";
			req_url = oauth_sign_url2(uri.c_str(), &postarg, OA_HMAC, 0, c_key.c_str(), c_secret.c_str(), t_key.c_str(), t_secret.c_str());
			reply2 = oauth_http_get(req_url.c_str(), postarg.c_str());

			FILE *APIsf;

			time(&local_t);
			local_st = localtime(&local_t);

			sprintf(filename, "rate_limit_status\\%04d%02d%02d%02d%02d%02d.json",
				local_st->tm_year+1900,
				local_st->tm_mon+1,
				local_st->tm_mday,
				local_st->tm_hour,
				local_st->tm_min,
				local_st->tm_sec);

			APIsf = fopen(filename, "w");

			fprintf(APIsf, "%s", reply2.c_str());

			fclose(APIsf);
			printf("completed\n");
		}

		if (!reply.c_str())
			printf("HTTP request for an oauth request-token failed.\n");
		else {
			//printf("HTTP-reply: %s\n", reply.c_str());

			printf("saving...");

			time(&local_t);
			local_st = localtime(&local_t);

			sprintf(filename, "Dat\\%04d%02d%02d%02d%02d%02d.json",
				local_st->tm_year+1900,
				local_st->tm_mon+1,
				local_st->tm_mday,
				local_st->tm_hour,
				local_st->tm_min,
				local_st->tm_sec);
			dlf = fopen(filename, "w");
			fprintf(dlf, "%s", reply.c_str());
			fclose(dlf);

			puts("completed");

			printf("parsing...");

			const char *string = reply.c_str();
			parse(v, string, string + strlen(string));

			picojson::array arr = v.get<picojson::array>();

			wlf=fopen("id.txt","a");

			for (picojson::array::const_iterator it = arr.begin(); it != arr.end(); ++it) {
				picojson::object obj = it->get<picojson::object>();
				std::string tempstring = obj["id_str"].to_str();
				const char *temp = tempstring.c_str();
				fprintf(wlf,"%s\n",temp);
			}

			fclose(wlf);

			//cur = v.get<picojson::object>()["next_cursor_str"].to_str();

			fgets(screen[0],20,tlf);

			puts("completed");
		}
		Sleep(15000);
	}
	fclose(tlf);
}

int main (int argc, char **argv)
{
	try {
		Socket::initialize();
		twitter_example();
	} catch (char const *error) {
		puts(error);
	}
	return 0;
}
