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
		fprintf(stderr, "[JSON_API_FILTER](%d)::" fmt "\n", __LINE__, ##__VA_ARGS__); \
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



#ifdef __cplusplus 
}
#endif
#endif
