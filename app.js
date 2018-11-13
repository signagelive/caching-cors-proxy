const express = require('express')
const apicache = require('apicache')
const crypto = require('crypto')
var httpProxy = require('http-proxy');
var config = require('./config.json')

var url = require('url');

const port = process.env.PORT || 8080;

let app = express()

// remove the x-powered by header
app.set('x-powered-by', false);

// configure the Express API Cache Middleware
let cache = apicache.options({
    debug: false,
    statusCodes: {
        exclude: [400, 401, 402, 403, 404, 429, 500], // list status codes to specifically exclude (e.g. [404, 403] cache all responses unless they had a 404 or 403 status)
        include: [], // list status codes to require (e.g. [200] caches ONLY responses with a success/200 code)
    },
    appendKey: function(req, res) {
        var key = "";
        var authHeader = req.headers["authorization"];
        if (authHeader)
            key += authHeader;

        var ip = (req.headers['x-forwarded-for'] ||
            req.connection.remoteAddress ||
            req.socket.remoteAddress ||
            req.connection.socket.remoteAddress).split(",")[0];

        if (ip)
            key += ip;

        const secret = config.encryptionKey;
        const hash = crypto.createHmac('sha256', secret).digest('hex');

        return hash;
    }
}).middleware


// GET apicache index (for the curious)
app.get('/api/cache/index', function(req, res, next) {
    var ip = (req.headers['x-forwarded-for'] ||
        req.connection.remoteAddress ||
        req.socket.remoteAddress ||
        req.connection.socket.remoteAddress).split(",")[0];

    res.send(apicache.getIndex());
});

// Catch and cache GET Requests
app.get('*', cache("5 minutes", isDomainCachable), (req, res) => {
    handleRequest(req, res)
});

// Catch and cache POST Requests
app.post('*', cache("5 minutes", isDomainCachable), (req, res) => {
    handleRequest(req, res)
});

// proxy OPTIONS but don't cache
app.options('*', (req, res) => {
    handleRequest(req, res)
});

// Start the Express Server
app.listen(port, () => {
    console.log(`Listening on: http://localhost:${port}`);
});

function handleRequest(req, res) {
    // Default options:
    var httpProxyOptions = {
        xfwd: true, // Append X-Forwarded-* headers
    };
    /* // Allow user to override defaults and add own options
     if (options.httpProxyOptions) {
         Object.keys(options.httpProxyOptions).forEach(function(option) {
             httpProxyOptions[option] = options.httpProxyOptions[option];
         });
     }*/
    var proxy = httpProxy.createServer(httpProxyOptions);
    var corsAnywhere = {
        //getProxyForUrl: getProxyForUrl, // Function that specifies the proxy to use
        maxRedirects: 5, // Maximum number of redirects to be followed.
        originBlacklist: [], // Requests from these origins will be blocked.
        originWhitelist: [], // If non-empty, requests not from an origin in this list will be blocked.
        checkRateLimit: null, // Function that may enforce a rate-limit by returning a non-empty string.
        redirectSameOrigin: false, // Redirect the client to the requested URL for same-origin requests.
        requireHeader: null, // Require a header to be set?
        removeHeaders: [], // Strip these request headers.
        setHeaders: {}, // Set these request headers.
        corsMaxAge: 0, // If set, an Access-Control-Max-Age header with this value (in seconds) will be added.
        helpFile: __dirname + '/help.txt',
    };

    /* Object.keys(corsAnywhere).forEach(function(option) {
         if (Object.prototype.hasOwnProperty.call(options, option)) {
             corsAnywhere[option] = options[option];
         }
     });*/

    // Convert corsAnywhere.requireHeader to an array of lowercase header names, or null.
    if (corsAnywhere.requireHeader) {
        if (typeof corsAnywhere.requireHeader === 'string') {
            corsAnywhere.requireHeader = [corsAnywhere.requireHeader.toLowerCase()];
        } else if (!Array.isArray(corsAnywhere.requireHeader) || corsAnywhere.requireHeader.length === 0) {
            corsAnywhere.requireHeader = null;
        } else {
            corsAnywhere.requireHeader = corsAnywhere.requireHeader.map(function(headerName) {
                return headerName.toLowerCase();
            });
        }
    }
    var hasRequiredHeaders = function(headers) {
        return !corsAnywhere.requireHeader || corsAnywhere.requireHeader.some(function(headerName) {
            return Object.hasOwnProperty.call(headers, headerName);
        });
    };

    req.corsAnywhereRequestState = {
        // getProxyForUrl: corsAnywhere.getProxyForUrl,
        maxRedirects: corsAnywhere.maxRedirects,
        corsMaxAge: corsAnywhere.corsMaxAge,
    };

    var cors_headers = withCORS({}, req);
    if (req.method === 'OPTIONS') {
        // Pre-flight request. Reply successfully:
        res.writeHead(200, cors_headers);
        res.end();
        return;
    }
    var location = parseURL(req.url.slice(1));

    if (!location) {
        // Invalid API call. Show how to correctly use the API
        res.writeHead(200, 'Url not set', cors_headers);
        res.end('Bad Request to CORS PROXY');
    }

    if (location.host === 'iscorsneeded') {
        // Is CORS needed? This path is provided so that API consumers can test whether it's necessary
        // to use CORS. The server's reply is always No, because if they can read it, then CORS headers
        // are not necessary.
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('no');
        return;
    }

    if (location.port > 65535) {
        // Port is higher than 65535
        res.writeHead(400, 'Invalid port', cors_headers);
        res.end('Port number too large: ' + location.port);
        return;
    }

    if (!/^\/https?:/.test(req.url) && !isValidHostName(location.hostname)) {
        // Don't even try to proxy invalid hosts (such as /favicon.ico, /robots.txt)
        res.writeHead(404, 'Invalid host', cors_headers);
        res.end('Invalid host: ' + location.hostname);
        return;
    }

    if (!hasRequiredHeaders(req.headers)) {
        res.writeHead(400, 'Header required', cors_headers);
        res.end('Missing required request header. Must specify one of: ' + corsAnywhere.requireHeader);
        return;
    }

    var origin = req.headers.origin || '';
    if (corsAnywhere.originBlacklist.indexOf(origin) >= 0) {
        res.writeHead(403, 'Forbidden', cors_headers);
        res.end('The origin "' + origin + '" was blacklisted by the operator of this proxy.');
        return;
    }

    if (corsAnywhere.originWhitelist.length && corsAnywhere.originWhitelist.indexOf(origin) === -1) {
        res.writeHead(403, 'Forbidden', cors_headers);
        res.end('The origin "' + origin + '" was not whitelisted by the operator of this proxy.');
        return;
    }

    var rateLimitMessage = corsAnywhere.checkRateLimit && corsAnywhere.checkRateLimit(origin);
    if (rateLimitMessage) {
        res.writeHead(429, 'Too Many Requests', cors_headers);
        res.end('The origin "' + origin + '" has sent too many requests.\n' + rateLimitMessage);
        return;
    }

    if (corsAnywhere.redirectSameOrigin && origin && location.href[origin.length] === '/' &&
        location.href.lastIndexOf(origin, 0) === 0) {
        // Send a permanent redirect to offload the server. Badly coded clients should not waste our resources.
        cors_headers.vary = 'origin';
        cors_headers['cache-control'] = 'private';
        cors_headers.location = location.href;
        res.writeHead(301, 'Please use a direct request', cors_headers);
        res.end();
        return;
    }

    var isRequestedOverHttps = req.connection.encrypted || /^\s*https/.test(req.headers['x-forwarded-proto']);
    var proxyBaseUrl = (isRequestedOverHttps ? 'https://' : 'http://') + req.headers.host;

    corsAnywhere.removeHeaders.forEach(function(header) {
        delete req.headers[header];
    });

    Object.keys(corsAnywhere.setHeaders).forEach(function(header) {
        req.headers[header] = corsAnywhere.setHeaders[header];
    });

    req.corsAnywhereRequestState.location = location;
    req.corsAnywhereRequestState.proxyBaseUrl = proxyBaseUrl;

    proxyRequest(req, res, proxy);
};

function parseURL(req_url) {
    var match = req_url.match(/^(?:(https?:)?\/\/)?(([^\/?]+?)(?::(\d{0,5})(?=[\/?]|$))?)([\/?][\S\s]*|$)/i);
    //                              ^^^^^^^          ^^^^^^^^      ^^^^^^^                ^^^^^^^^^^^^
    //                            1:protocol       3:hostname     4:port                 5:path + query string
    //                                              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //                                            2:host
    if (!match) {
        return null;
    }
    if (!match[1]) {
        // Scheme is omitted.
        if (req_url.lastIndexOf('//', 0) === -1) {
            // "//" is omitted.
            req_url = '//' + req_url;
        }
        req_url = (match[4] === '443' ? 'https:' : 'http:') + req_url;
    }
    return url.parse(req_url);
}

function onProxyResponse(proxy, proxyReq, proxyRes, req, res) {
    var requestState = req.corsAnywhereRequestState;

    var statusCode = proxyRes.statusCode;

    if (!requestState.redirectCount_) {
        res.setHeader('x-request-url', requestState.location.href);
    }
    // Handle redirects
    if (statusCode === 301 || statusCode === 302 || statusCode === 303 || statusCode === 307 || statusCode === 308) {
        var locationHeader = proxyRes.headers.location;
        if (locationHeader) {
            locationHeader = url.resolve(requestState.location.href, locationHeader);

            if (statusCode === 301 || statusCode === 302 || statusCode === 303) {
                // Exclude 307 & 308, because they are rare, and require preserving the method + request body
                requestState.redirectCount_ = requestState.redirectCount_ + 1 || 1;
                if (requestState.redirectCount_ <= requestState.maxRedirects) {
                    // Handle redirects within the server, because some clients (e.g. Android Stock Browser)
                    // cancel redirects.
                    // Set header for debugging purposes. Do not try to parse it!
                    res.setHeader('X-CORS-Redirect-' + requestState.redirectCount_, statusCode + ' ' + locationHeader);

                    req.method = 'GET';
                    req.headers['content-length'] = '0';
                    delete req.headers['content-type'];
                    requestState.location = parseURL(locationHeader);

                    // Remove all listeners (=reset events to initial state)
                    req.removeAllListeners();

                    // Remove the error listener so that the ECONNRESET "error" that
                    // may occur after aborting a request does not propagate to res.
                    // https://github.com/nodejitsu/node-http-proxy/blob/v1.11.1/lib/http-proxy/passes/web-incoming.js#L134
                    proxyReq.removeAllListeners('error');
                    proxyReq.once('error', function catchAndIgnoreError() {});
                    proxyReq.abort();

                    // Initiate a new proxy request.
                    proxyRequest(req, res, proxy);
                    return false;
                }
            }
            proxyRes.headers.location = requestState.proxyBaseUrl + '/' + locationHeader;
        }
    }

    // Strip cookies
    delete proxyRes.headers['set-cookie'];
    delete proxyRes.headers['set-cookie2'];

    proxyRes.headers['x-final-url'] = requestState.location.href;
    withCORS(proxyRes.headers, req);
    return true;
}

function isValidHostName(hostname) {
    /*return !!(
        regexp_tld.test(hostname) ||
        net.isIPv4(hostname) ||
        net.isIPv6(hostname)
    );*/

    return true
}

/**
 * Adds CORS headers to the response headers.
 *
 * @param headers {object} Response headers
 * @param request {ServerRequest}
 */
function withCORS(headers, request) {
    headers['access-control-allow-origin'] = '*';
    var corsMaxAge = request.corsAnywhereRequestState.corsMaxAge;
    if (corsMaxAge) {
        headers['access-control-max-age'] = corsMaxAge;
    }
    if (request.headers['access-control-request-method']) {
        headers['access-control-allow-methods'] = request.headers['access-control-request-method'];
        delete request.headers['access-control-request-method'];
    }
    if (request.headers['access-control-request-headers']) {
        headers['access-control-allow-headers'] = request.headers['access-control-request-headers'];
        delete request.headers['access-control-request-headers'];
    }

    headers['access-control-expose-headers'] = Object.keys(headers).join(',');

    return headers;
}

/**
 * Performs the actual proxy request.
 *
 * @param req {ServerRequest} Incoming http request
 * @param res {ServerResponse} Outgoing (proxied) http request
 * @param proxy {HttpProxy}
 */
function proxyRequest(req, res, proxy) {
    var location = req.corsAnywhereRequestState.location;
    req.url = location.path;

    var proxyOptions = {
        changeOrigin: false,
        prependPath: false,
        target: location,
        headers: {
            host: location.host,
        },
        // HACK: Get hold of the proxyReq object, because we need it later.
        // https://github.com/nodejitsu/node-http-proxy/blob/v1.11.1/lib/http-proxy/passes/web-incoming.js#L144
        buffer: {
            pipe: function(proxyReq) {
                var proxyReqOn = proxyReq.on;
                // Intercepts the handler that connects proxyRes to res.
                // https://github.com/nodejitsu/node-http-proxy/blob/v1.11.1/lib/http-proxy/passes/web-incoming.js#L146-L158
                proxyReq.on = function(eventName, listener) {
                    if (eventName !== 'response') {
                        return proxyReqOn.call(this, eventName, listener);
                    }
                    return proxyReqOn.call(this, 'response', function(proxyRes) {
                        if (onProxyResponse(proxy, proxyReq, proxyRes, req, res)) {
                            try {
                                listener(proxyRes);
                            } catch (err) {
                                // Wrap in try-catch because an error could occur:
                                // "RangeError: Invalid status code: 0"
                                // https://github.com/Rob--W/cors-anywhere/issues/95
                                // https://github.com/nodejitsu/node-http-proxy/issues/1080

                                // Forward error (will ultimately emit the 'error' event on our proxy object):
                                // https://github.com/nodejitsu/node-http-proxy/blob/v1.11.1/lib/http-proxy/passes/web-incoming.js#L134
                                proxyReq.emit('error', err);
                            }
                        }
                    });
                };
                return req.pipe(proxyReq);
            },
        },
    };

    /*var proxyThroughUrl = req.corsAnywhereRequestState.getProxyForUrl(location.href);
    if (proxyThroughUrl) {
        proxyOptions.target = proxyThroughUrl;
        proxyOptions.toProxy = true;
        // If a proxy URL was set, req.url must be an absolute URL. Then the request will not be sent
        // directly to the proxied URL, but through another proxy.
        req.url = location.href;
    }*/

    // Start proxying the request
    proxy.web(req, res, proxyOptions);
}

// used by the caching middleware to determine if a responses from a domain should be cached or not.
function isDomainCachable(req, res) {
    var finalUrlHeader = res.getHeader('x-final-url');
    if (finalUrlHeader != null) {
        var finalUrl = url.parse(res.getHeader('x-final-url'));

        // is the host in the list of domains we should not cache?
        var dontCacheHosts = require('./dont-cache')

        if (dontCacheHosts.indexOf(finalUrl.host) >= 0) {
            // in the list of domains to not cache - so don't cache the response
            return false
        } else {
            return true
        }
    } else {
        // cache by default - we know that if the header is not included then this is a cached response from a previous request
        return true;
    }
}