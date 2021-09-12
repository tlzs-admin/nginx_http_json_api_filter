
### I. build and install nginx dynamic module (debian 11)

1. download nginx source code

```
$ cd <work_path>
$ wget https://github.com/nginx/nginx/archive/refs/tags/release-1.18.0.tar.gz
$ export nginx_source_dir=$(pwd)/nginx-release-1.18.0
$ export nginx_modules_dir=/usr/share/nginx/modules

```

2. build dynamic module

```
$ mkdir -p projects && cd projects 
$ pwd
$ git clone $repo_url
$ export projects_dir=$(pwd)
$ export dyn_module_path=${projects_dir}/nginx_http_json_api_filter

$ cd $nginx_source_dir
$ make clean
$ auto/configure --with-compat  \
    --add-dynamic-module="$dyn_module_path"
    --with-cc-opt="-g -D_DEBUG"
    
```


3. make a symbolic link for testing
( or copy the .so file to the nginx_modules_dir)

```
$ test -e $nginx_modules_dir/ngx_http_jwt_auth_rs256_module.so \
  || ln -s $(pwd)/objs/ngx_http_jwt_auth_rs256_module.so $nginx_modules_dir/

```

### II. build and run upstream app

```
$ cd ${projects_dir}/nginx_http_json_api_filter/upstream
$ make
$ ./auth_proxy &

```

### III. Nginx configure examples
- conf/nginx.conf.example
- conf/site-enabled-default.example


