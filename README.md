

To prevent a domain from caching
1. Add the domain to the list of domains in dont-cache.json
2. Restart the server (if running using pm2) `pm2 reload all` will restart the process and reload the config