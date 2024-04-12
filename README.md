# ngx_http_js_challenge_module

[![GitHub License](https://img.shields.io/github/license/simon987/ngx_http_js_challenge_module.svg)](LICENSE)
[![CodeFactor](https://www.codefactor.io/repository/github/simon987/ngx_http_js_challenge_module/badge)](https://www.codefactor.io/repository/github/simon987/ngx_http_js_challenge_module)
[![Demo Website](https://img.shields.io/badge/demo-website-blue.svg)](https://ngx-js-demo.simon987.net/)

Simple JavaScript proof-of-work based access control for Nginx, designed to provide security with minimal overhead.

## Features

- **Lightweight Integration:** Easy to integrate with existing Nginx installations.
- **Configurable Security:** Flexible settings to adjust security strength and client experience.
- **Minimal Performance Impact:** Designed to operate with virtually no additional server load.

## Quick Start

1. **Installation**
   Add the following line to your `nginx.conf`:
   ```
   load_module /path/to/ngx_http_js_challenge_module.so;
   ```

2. **Configuration**
   Use the simple or advanced configurations provided below to customize the module to your needs.

## Installation

To install the ngx_http_js_challenge_module, follow these steps:

1. Add the module loading directive to your Nginx configuration file (`/etc/nginx/nginx.conf`):
   ```
   load_module /path/to/ngx_http_js_challenge_module.so;
   ```

2. Apply the changes by reloading Nginx:
   ```
   nginx -s reload
   ```

## Configuration

### Basic Configuration

For basic setup, update your server block as follows:

```
server {
    js_challenge on;
    js_challenge_secret "change me!";  # Ensure to replace this with a strong secret in production
}
```

### Advanced Configuration

For more complex setups, including exemptions for specific paths:

```
server {
    js_challenge on;
    js_challenge_secret "change me!";
    js_challenge_html "/path/to/body.html";
    js_challenge_bucket_duration 3600;
    js_challenge_title "Verifying your browser...";

    location /static {
        js_challenge off;
        alias /static_files/;
    }

    location /sensitive {
        js_challenge_bucket_duration 600;
        # Add further customization here
    }
}
```

### Parameters

- **js_challenge on|off** Toggle javascript challenges for this config block
- **js_challenge_secret "secret"** Secret for generating the challenges. DEFAULT: "changeme"
- **js_challenge_html "/path/to/file.html"** Path to html file to be inserted in the `<body>` tag of the interstitial page
- **js_challenge_title "title"** Will be inserted in the `<title>` tag of the interstitial page. DEFAULT: "Verifying your browser..."
- **js_challenge_bucket_duration time** Interval to prompt js challenge, in seconds. DEFAULT: 3600

### Installation

1. Add `load_module ngx_http_js_challenge_module.so;` to `/etc/nginx/nginx.conf`
2. Reload `nginx -s reload`

### Build from source

These steps have to be performed on machine with compatible configuration (same nginx, glibc, openssl version etc.)

1. Install dependencies
    ```
    apt install libperl-dev libgeoip-dev libgd-dev libxslt1-dev libpcre3-dev
    ```
2. Download nginx tarball corresponding to your current version (Check with `nginx -v`)
    ```
    wget https://nginx.org/download/nginx-1.25.4.tar.gz
    tar -xzf nginx-1.25.4.tar.gz
    export NGINX_PATH=$(pwd)/nginx-1.25.4/
    ```
3. Compile the module
    ```
    git clone https://github.com/simon987/ngx_http_js_challenge_module
    cd ngx_http_js_challenge_module
    ./build.sh
    ```
4. The dynamic module can be found at `${NGINX_PATH}/objs/ngx_http_js_challenge_module.so`

### Known limitations (To Do)

* None

### Throughput
<p align="center">
  <img width="600px" src="throughput.png"/>
</p>