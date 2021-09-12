#ifndef NGX_HTTP_JSON_API_FILTER_H_
#define NGX_HTTP_JSON_API_FILTER_H_

#ifdef __cplusplus 
extern "C" {
#endif

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifdef _DEBUG
#define debug_printf(fmt, ...) do { \
		fprintf(stderr, "%s(%d)::" fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
} while(0)
#else
#define debug_printf(fmt, ...) do { } while(0)
#endif

struct json_api_filter_conf {
	ngx_str_t uri;
	ngx_array_t * settings;
};

struct json_api_filter_setting
{
	ngx_int_t index;
	ngx_http_complex_value_t value;
	ngx_http_set_variable_pt set_handler;
};

typedef struct json_api_filter_context
{
	struct json_api_filter_conf conf[1];
	void * user_data;
	ngx_uint_t done;
	ngx_uint_t status;
	ngx_http_request_t * auth_request;
	ngx_http_request_t * upstream_filter_request;
	
	ngx_int_t (* process)(ngx_conf_t * cf, ngx_command_t * cmd, void * user_data);
}json_api_filter_context_t;

json_api_filter_context_t * json_api_filter_context_init(json_api_filter_context_t * ctx, ngx_conf_t * cf);
void json_api_filter_context_cleanup(json_api_filter_context_t * ctx);



#ifdef __cplusplus 
}
#endif
#endif
