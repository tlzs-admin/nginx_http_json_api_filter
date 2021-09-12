/*
 * auth_proxy.c
 * 
 * Copyright 2021 chehw <hongwei.che@gmail.com>
 * 
 * The MIT License (MIT)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy 
 * of this software and associated documentation files (the "Software"), to deal 
 * in the Software without restriction, including without limitation the rights 
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
 * copies of the Software, and to permit persons to whom the Software is 
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all 
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
 * IN THE SOFTWARE.
 * 
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <libsoup/soup.h>

static void on_document_root();

int main(int argc, char **argv)
{
	SoupServer * server = soup_server_new(SOUP_SERVER_SERVER_HEADER, "jwt_auth_proxy", NULL);
	assert(server);
	
	GMainLoop * loop = NULL;
	GError * gerr = NULL;
	soup_server_add_handler(server, "/", on_document_root, NULL, NULL);
	gboolean ok = soup_server_listen_all(server, 8000, 0, &gerr);
	if(!ok || gerr) {
		if(gerr) {
			fprintf(stderr, "[ERROR]: %s\n", gerr->message);
			g_error_free(gerr);
		}
		exit(1);
	}
	
	loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(loop);
	
	g_main_loop_unref(loop);
	
	return 0;
}

static void on_document_root(SoupServer * server, SoupMessage * msg, const char * path, 
	GHashTable * query, SoupClientContext * client, void * user_data)
{
	SoupMessageHeaders * in_hdrs = msg->request_headers;
	SoupMessageHeadersIter iter;
	soup_message_headers_iter_init(&iter, in_hdrs);
	const char * name = NULL;
	const char * value = NULL;
	while(soup_message_headers_iter_next(&iter, &name, &value)) {
		
		printf("%s: %s\n", name, value);
		name = NULL;
		value = NULL;
	}
	
	printf("method: %s\n", msg->method);
	
	soup_message_set_response(msg, "text/plain", SOUP_MEMORY_COPY, 
		"auth\n", 5);
	soup_message_set_status(msg, SOUP_STATUS_OK);
}
