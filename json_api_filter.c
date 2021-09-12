/*
 * json_api_filter.c
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

#include "json_api_filter.h"

#include <stdarg.h>


static ngx_int_t on_module_init_master(ngx_log_t * log)
{
	debug_printf("%s()", __FUNCTION__);
	return NGX_OK;
}
static ngx_int_t on_module_init_module(ngx_cycle_t * cycle)
{
	debug_printf("%s()", __FUNCTION__);
	return NGX_OK;
}
static ngx_int_t on_module_init_process(ngx_cycle_t * cycle)
{
	debug_printf("%s()", __FUNCTION__);
	return NGX_OK;
}
static ngx_int_t on_module_init_thread(ngx_cycle_t * cycle)
{
	debug_printf("%s()", __FUNCTION__);
	return NGX_OK;
}
static void      on_module_exit_thread(ngx_cycle_t * cycle)
{
	debug_printf("%s()", __FUNCTION__);
	return;
}
static void      on_module_exit_process(ngx_cycle_t * cycle)
{
	debug_printf("%s()", __FUNCTION__);
	return;
}
static void      on_module_exit_master(ngx_cycle_t * cycle)
{
	debug_printf("%s()", __FUNCTION__);
	return;
}

static char * json_api_filter(ngx_conf_t * cf, ngx_command_t * cmd, void * user_conf);

static ngx_command_t s_module_commands[] = {
	[0] = {
		.name = ngx_string("json_api_filter"),
		.type = NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		.set = json_api_filter,
		.conf = NGX_HTTP_LOC_CONF_OFFSET,
		.offset = 0,
		.post = NULL,
	},
	
	ngx_null_command,
};


static void * on_http_module_create_loc_conf(ngx_conf_t * cf);
static char * on_http_module_merge_loc_conf(ngx_conf_t * cf, void * parent, void * child);
static ngx_http_module_t s_module_ctx[1] = {{
	//~ .preconfiguration = on_http_module_preconfiguration,
	//~ .postconfiguration = on_http_module_postconfiguration,
	//~ .create_main_conf = on_http_module_create_main_conf,
	//~ .init_main_conf= on_init_main_conf,
	.create_loc_conf = on_http_module_create_loc_conf,
	.merge_loc_conf = on_http_module_merge_loc_conf,
}};

ngx_module_t ngx_http_json_api_filter_module = {
	NGX_MODULE_V1,
	.ctx = s_module_ctx,
	.commands = s_module_commands,
	.type = NGX_HTTP_MODULE,
	
	.init_master  = on_module_init_master,
	.init_module  = on_module_init_module,
	.init_process = on_module_init_process,
	.init_thread  = on_module_init_thread,
	.exit_thread  = on_module_exit_thread,
	.exit_process = on_module_exit_process,
	.exit_master  = on_module_exit_master,
	NGX_MODULE_V1_PADDING
};

static char * json_api_filter(ngx_conf_t * cf, ngx_command_t * cmd, void * user_data) 
{
	debug_printf("%s(user_conf=%p)", __FUNCTION__, user_data);
	
	json_api_filter_context_t * ctx = user_data;
	if(NULL == ctx) return "create_loc_conf() function error (or not implemented)";
	
	struct json_api_filter_conf * conf = ctx->conf;
	if(conf->uri.data != NULL) return "is duplicated.";
	
	ngx_str_t *args = cf->args->elts;
	if(ngx_strcmp(args[1].data, "off") == 0) {
		conf->uri.len = 0;
		conf->uri.data = (u_char *)"";
		return NGX_CONF_OK;
	}
	
	conf->uri = args[1];
	
	debug_printf("conf->uri: %.*s", (int)conf->uri.len, (char *)conf->uri.data);
	
	return NGX_CONF_OK;
}


static void * on_http_module_create_loc_conf(ngx_conf_t * cf)
{
	json_api_filter_context_t * ctx = json_api_filter_context_init(NULL, cf);
	
	debug_printf("%s(%p): ctx=%p", __FUNCTION__, cf, ctx);
	
	return ctx;
}

static char * on_http_module_merge_loc_conf(ngx_conf_t * cf, void * parent, void * child)
{
	struct json_api_filter_conf * prev = parent;
	struct json_api_filter_conf * current = child;
	
	ngx_conf_merge_str_value(current->uri, prev->uri, "");
	ngx_conf_merge_ptr_value(current->settings, prev->settings, NULL);
	
	debug_printf("%s(%p): parent=%p, parent_uri=%.*s, parent_settings=%p | child=%p", __FUNCTION__, cf, 
		parent, (int)prev->uri.len, (char *)prev->uri.data,
		prev->settings,
		child);
	
	return NGX_CONF_OK;
}


json_api_filter_context_t * json_api_filter_context_init(json_api_filter_context_t * ctx, ngx_conf_t * cf)
{
	if(NULL == ctx) {
		ctx = ngx_pcalloc(cf->pool, sizeof(*ctx));
	}
	if(NULL == ctx) return NULL;
	
	ctx->conf->settings = NGX_CONF_UNSET_PTR;
	return ctx;
}
