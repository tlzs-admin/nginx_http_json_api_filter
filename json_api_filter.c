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

typedef struct json_api_filter_context
{
	void * user_data;
	ngx_http_request_t * request;
	struct json_api_filter_conf * conf;
	
	struct {
		ngx_uint_t done;
		ngx_uint_t status;
		ngx_http_request_t * subrequest;
		
		ngx_int_t (* verify)(struct json_api_filter_context *ctx);
		ngx_int_t (* on_final)(ngx_http_request_t * request, void * data, ngx_int_t rc);
	}auth;
	
	struct {
		ngx_uint_t done;
		ngx_uint_t statue;
		ngx_http_request_t * subrequest;
		ngx_int_t (* filter)(struct json_api_filter_context * ctx);
	}upstream;
	
	ngx_int_t (* process)(ngx_conf_t * cf, ngx_command_t * cmd, void * user_data);
}json_api_filter_context_t;

static json_api_filter_context_t * json_api_filter_context_new(ngx_http_request_t * request, void * user_data);
//~ static void json_api_filter_context_cleanup(json_api_filter_context_t * ctx);


/************************************************************************
 * custom handlers
************************************************************************/
static ngx_int_t verify_jwt_token(ngx_http_request_t * request);
static char * json_api_filter(ngx_conf_t * cf, ngx_command_t * cmd, void * user_conf);

/************************************************************************
 * ngx module callbacks
************************************************************************/
static ngx_int_t on_module_init_master(ngx_log_t * log);
static ngx_int_t on_module_init_module(ngx_cycle_t * cycle);
static ngx_int_t on_module_init_process(ngx_cycle_t * cycle);
static ngx_int_t on_module_init_thread(ngx_cycle_t * cycle);
static void      on_module_exit_thread(ngx_cycle_t * cycle);
static void      on_module_exit_process(ngx_cycle_t * cycle);
static void      on_module_exit_master(ngx_cycle_t * cycle);

/************************************************************************
 * ngx module callbacks
************************************************************************/
static ngx_int_t on_http_module_postconfiguration(ngx_conf_t *cf);
static void * on_http_module_create_loc_conf(ngx_conf_t *cf);
static char * on_http_module_merge_loc_conf(ngx_conf_t *cf, void * parent, void * child);


/************************************************************************
 * Global Static Variables: 
************************************************************************/
static ngx_command_t s_module_commands[] = {
	[0] = {
		.name = ngx_string("json_api_filter"),
		.type = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		.set = json_api_filter,
		.conf = NGX_HTTP_LOC_CONF_OFFSET,
		.offset = 0,
		.post = NULL,
	},
	
	ngx_null_command,
};

static ngx_http_module_t s_module_ctx[1] = {{
	//~ .preconfiguration = on_http_module_preconfiguration,
	.postconfiguration = on_http_module_postconfiguration,
	//~ .create_main_conf = on_http_module_create_main_conf,
	//~ .init_main_conf= on_init_main_conf,
	.create_loc_conf = on_http_module_create_loc_conf,
	.merge_loc_conf = on_http_module_merge_loc_conf,
}};

/**
 * Shared symbol for nginx 
**/
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


/************************************************************************
 * custom module command handler: 
 * 
 * - Handler: json_api_filter: 
 * 
 * - Usuage:  (site_enabled/<site>.conf)
 * location [api_path] {
 * 	  json_api_filter [upstream_filter_uri];
 * }
************************************************************************/
static char * json_api_filter(ngx_conf_t * cf, ngx_command_t * cmd, void * user_data) 
{
	debug_printf("%s(user_conf=%p)", __FUNCTION__, user_data);
	
	struct json_api_filter_conf * conf = user_data;
	if(NULL == conf) return "create_loc_conf() function error (or not implemented)";
	
	
	if(conf->uri.data != NULL) return "is duplicated.";
	
	ngx_str_t *args = cf->args->elts;
	int num_args = cf->args->nelts;
	if(num_args != 2) return "invalid args count.";
	
	if(ngx_strcmp(args[1].data, "off") == 0) {
		conf->uri.len = 0;
		conf->uri.data = (u_char *)"";
		return NGX_CONF_OK;
	}

	conf->uri = args[1];
	
	debug_printf("conf->uri: %.*s", (int)conf->uri.len, (char *)conf->uri.data);
	
	return NGX_CONF_OK;
}

/************************************************************************
 * ngx module callbacks
************************************************************************/
static ngx_int_t on_module_init_master(ngx_log_t * log)
{
	debug_printf("%s()", __FUNCTION__);
	return NGX_OK;
}
static ngx_int_t on_module_init_module(ngx_cycle_t * cycle)
{
	debug_printf("%s(cycle=%p)", __FUNCTION__, cycle);
	return NGX_OK;
}
static ngx_int_t on_module_init_process(ngx_cycle_t * cycle)
{
	debug_printf("%s(cycle=%p)", __FUNCTION__, cycle);
	return NGX_OK;
}
static ngx_int_t on_module_init_thread(ngx_cycle_t * cycle)
{
	debug_printf("%s(cycle=%p)", __FUNCTION__, cycle);
	return NGX_OK;
}
static void      on_module_exit_thread(ngx_cycle_t * cycle)
{
	debug_printf("%s(cycle=%p)", __FUNCTION__, cycle);
	return;
}
static void      on_module_exit_process(ngx_cycle_t * cycle)
{
	debug_printf("%s(cycle=%p)", __FUNCTION__, cycle);
	return;
}
static void      on_module_exit_master(ngx_cycle_t * cycle)
{
	debug_printf("%s(cycle=%p)", __FUNCTION__, cycle);
	return;
}


/************************************************************************
 * ngx http_module callbacks
************************************************************************/

static ngx_http_request_body_filter_pt s_next_request_body_filter;
static ngx_http_output_body_filter_pt s_next_output_body_filter;
static ngx_http_output_header_filter_pt s_next_output_header_filter;

static ngx_int_t 
register_http_phase_handler(ngx_http_core_main_conf_t * main_conf, ngx_http_phases phase, ngx_http_handler_pt handler)
{
	assert(phase >= 0 && phase <= NGX_HTTP_LOG_PHASE);
	if(NULL == main_conf) return NGX_ERROR;
	
	ngx_http_handler_pt * p_handler = ngx_array_push(&main_conf->phases[phase].handlers);
	if(NULL == p_handler) return NGX_ERROR;
	
	*p_handler = handler;
	return NGX_OK;
}


static ngx_int_t on_http_module_postconfiguration(ngx_conf_t * cf)
{
	ngx_int_t ret = NGX_ERROR;
	debug_printf("%s(%p)", __FUNCTION__, cf);
	
	ngx_http_core_main_conf_t * http_main_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
	ret = register_http_phase_handler(http_main_conf, NGX_HTTP_ACCESS_PHASE, verify_jwt_token);
	if(ret != NGX_OK) return ret;
	
	
	// save current filters chain
	s_next_request_body_filter = ngx_http_top_request_body_filter;
	s_next_output_body_filter = ngx_http_top_body_filter;
	s_next_output_header_filter = ngx_http_top_header_filter;
	
	// set custom filter on top of the filters chain
	// ngx_http_top_request_body_filter = my_request_body_filter;
	
	return NGX_OK;
}


static void * on_http_module_create_loc_conf(ngx_conf_t * cf)
{
	struct json_api_filter_conf *conf = ngx_pcalloc(cf->pool, sizeof(*conf));
	debug_printf("%s(%p): conf=%p", __FUNCTION__, cf, conf);
	
	if(NULL == conf) return NULL;
	conf->settings = NGX_CONF_UNSET_PTR;

	return conf;
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

static ngx_int_t auth_verify(json_api_filter_context_t * ctx);
static ngx_int_t on_auth_verify_final(ngx_http_request_t * request, void * data, ngx_int_t rc);
static ngx_int_t upstream_filter(json_api_filter_context_t * ctx);
static json_api_filter_context_t * json_api_filter_context_new(ngx_http_request_t * request, void * user_data)
{
	assert(request);
	struct json_api_filter_conf * conf = ngx_http_get_module_loc_conf(request, ngx_http_json_api_filter_module);
	if(NULL == conf) return NULL;
	
	json_api_filter_context_t * ctx = ngx_pcalloc(request->pool, sizeof(*ctx));
	if(NULL == ctx) return NULL;
	
	ctx->request = request;
	ctx->conf = conf;
	ctx->user_data = user_data;
	
	ctx->auth.verify = auth_verify;
	ctx->auth.on_final = on_auth_verify_final;
	
	ctx->upstream.filter = upstream_filter;
	
	// init ctx->auth
	{
		ngx_http_post_subrequest_t * post_request = ngx_pcalloc(request->pool, sizeof(*post_request));
		if(NULL == post_request) return NULL;
		post_request->handler = ctx->auth.on_final;
		post_request->data = ctx;
		
		ngx_http_request_t * subrequest = NULL;
		if(ngx_http_subrequest(request, &conf->uri, NULL, &subrequest, post_request, NGX_HTTP_SUBREQUEST_WAITED) != NGX_OK) {
			return NULL;
		}
		subrequest->request_body = ngx_pcalloc(request->pool, sizeof(*subrequest->request_body));
		if(NULL == subrequest->request_body) return NULL;
		
		subrequest->header_only = 1;
		ctx->auth.subrequest = subrequest;
		ngx_http_set_ctx(request, ctx, ngx_http_json_api_filter_module);
		return ctx;
	}

	return ctx;
}

//~ static void json_api_filter_context_cleanup(json_api_filter_context_t * ctx)
//~ {
	//~ return;
//~ }

static ngx_int_t on_auth_verify_final(ngx_http_request_t * request, void * user_data, ngx_int_t rc)
{
	json_api_filter_context_t * ctx = user_data;
	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, request->connection->log, 0, "%s():status=%d", 
		__FUNCTION__, request->headers_out.status);
	
	ctx->auth.done = 1;
	ctx->auth.status = request->headers_out.status;
	return rc;
}

static ngx_int_t auth_verify(json_api_filter_context_t * ctx)
{
	if(!ctx->auth.done) return NGX_AGAIN;
	
	ngx_http_request_t * request = ctx->request; 
	ngx_int_t status = ctx->auth.status;
	if(status >= NGX_HTTP_OK && status < NGX_HTTP_SPECIAL_RESPONSE) return NGX_OK;
	
	switch(status) {
		case NGX_HTTP_FORBIDDEN: return status;
		case NGX_HTTP_UNAUTHORIZED: break;
		default: return NGX_ERROR;
	}
	
	ngx_http_request_t * auth_request = ctx->auth.subrequest;
	assert(auth_request);
	
	ngx_table_elt_t * www_authenticate = NULL, *p_hdr = NULL;
	www_authenticate = auth_request->headers_out.www_authenticate;
	if(NULL == www_authenticate && auth_request->upstream) {
		www_authenticate = auth_request->upstream->headers_in.www_authenticate;
	}
	
	if(www_authenticate) {
		// append www_authenticate header to the response headers
		p_hdr = ngx_list_push(&request->headers_out.headers);
		if(NULL == p_hdr) return NGX_ERROR;
		*p_hdr = *www_authenticate;
		request->headers_out.www_authenticate = p_hdr;
	}
	
	return status;
}

static ngx_int_t upstream_filter(json_api_filter_context_t * ctx)
{
	// todo
	return NGX_OK;
}

/**
 * json_api_module::verify_jwt_token(upstream_uri)
 * 
 * use upstream proxy to verify jwt token
**/
static ngx_int_t verify_jwt_token(ngx_http_request_t * request)
{
	debug_printf("%s(request=%p)", __FUNCTION__, request); 
	
	ngx_int_t ret = NGX_OK;
	json_api_filter_context_t * ctx = ngx_http_get_module_ctx(request, ngx_http_json_api_filter_module);
	
	if(NULL == ctx) {
		ctx = json_api_filter_context_new(request, NULL);
		if(NULL == ctx) return NGX_ERROR;
		
		fprintf(stderr, "NGX_AGAIN\n");
		return NGX_EAGAIN;
	}
	
	ret = ctx->auth.verify(ctx);
	if(ret != NGX_OK) return ret;
	
	ret = ctx->upstream.filter(ctx);
	if(ret != NGX_OK) return ret;
	
	return NGX_OK;
}
