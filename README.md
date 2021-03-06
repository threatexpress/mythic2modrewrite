# mythic2modrewrite
Generate Apache mod_rewrite rules for Mythic C2 profiles

**Work in progress** 
Currently only supports ruleset generation for the "http" C2 profile type

This project converts a Mythic payload config to a functional mod_rewrite `.htaccess` to support HTTP reverse proxy redirection to a Cobalt Strike teamserver. The use of reverse proxies provides protection to backend C2 servers from profiling, investigation, and general internet background radiation.

As of [Mythic 2.2.12](https://bloodhoundhq.slack.com/archives/CHG769BL2/p1626822877094500) redirect rule creation is enabled automatically for the `http` C2 profile. Futhermore, you can now [add these to your own custom C2 profiles](https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/server-side-coding/redirect-rules). 

***Note***: You should test and tune the output as needed before deploying, but this script should handle the heavy lifting.

## Features

- Mythic "http" C2 Profile config parsing
 

## Quick start

A `http.json` config example is included for a quick test.

0) Export Payload Config - Once you generate a Mythic agent with whatever config you want, you can go to the "Created Payloads" page, select the dropdown next to your payload, and click "Export Payload Config". You'll get something like:
```{
    "payload_type": "apfell",
    "c2_profiles": [
        {
            "c2_profile": "http",
            "c2_profile_parameters": {
                "callback_port": "80",
                "killdate": "2022-06-23",
                "encrypted_exchange_check": "T",
                "callback_jitter": "23",
                "headers": [
                    {
                        "name": "User-Agent",
                        "key": "User-Agent",
                        "value": "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
                        "custom": false
                    },
                    {
                        "name": "Host",
                        "key": "Host",
                        "value": "asdf",
                        "custom": false
                    },
                    {
                        "name": "*",
                        "key": "my key",
                        "value": "my value",
                        "custom": true
                    }
                ],
                "AESPSK": "aes256_hmac",
                "callback_host": "https://domain.com",
                "get_uri": "index",
                "post_uri": "data",
                "query_path_name": "q",
                "proxy_host": "",
                "proxy_port": "",
                "proxy_user": "",
                "proxy_pass": "",
                "callback_interval": "10"
            }
        }
    ],
    "commands": [
        "cat",.....<snip>
```
1) Run the script against a payload config
2) Save the output to `.htaccess` on your redirector
3) Modify as needed
4) Reload/restart the web server

## Apache mod_rewrite Example Usage

```
python3 mythic2modrewrite.py -i http.json -c https://TEAMSERVER -r https://GOHERE > /var/www/html/.htaccess
#### Save the following as .htaccess in the root web directory (i.e. /var/www/html/.htaccess)

########################################
## .htaccess START 
RewriteEngine On
## Uncomment to enable verbose debugging in /var/logs/apache2/error.log
# LogLevel alert rewrite:trace5
## (Optional)
## Scripted Web Delivery 
## Uncomment and adjust as needed
#RewriteCond %{REQUEST_URI} ^/css/style1.css?$
#RewriteCond %{HTTP_USER_AGENT} ^$
#RewriteRule ^.*$ "http://TEAMSERVER%{REQUEST_URI}" [P,L]


## C2 Traffic (HTTP-GET, HTTP-POST, HTTP-STAGER URIs)
## Logic: If a requested URI AND the User-Agent matches, proxy the connection to the Teamserver
## Consider adding other HTTP checks to fine tune the check.  (HTTP Cookie, HTTP Referer, HTTP Query String, etc)
## Refer to http://httpd.apache.org/docs/current/mod/mod_rewrite.html
## Profile URIs
RewriteCond %{REQUEST_URI} ^(/include/template/isx.php.*|/wp06/wp-includes/po.php.*|/wp08/wp-includes/dtcla.php.*|/modules/mod_search.php.*|/blog/wp-includes/pomo/src.php.*|/includes/phpmailer/class.pop3.php.*|/api/516280565958.*|/api/516280565959.*)$
## Profile UserAgent
RewriteCond %{HTTP_USER_AGENT} "Mozilla/5.0 \(Windows; U; MSIE 7.0; Windows NT 5.2\) Java/1.5.0_08"
RewriteRule ^.*$ "https://TEAMSERVER%{REQUEST_URI}" [P,L]

## Redirect all other traffic here (Optional)
RewriteRule ^.*$ HTTPS://GOHERE/ [L,R=302]

## .htaccess END
########################################
```
## Apache Rewrite Setup and Tips

### Enable Rewrite and Proxy
    apt-get install apache2
    a2enmod rewrite headers proxy proxy_http ssl cache
    a2dismod -f deflate
    service apache2 reload

**Note:** https://bluescreenofjeff.com/2016-06-28-cobalt-strike-http-c2-redirectors-with-apache-mod_rewrite/
"e0x70i pointed out in the comments below that if your Cobalt Strike Malleable C2 profile contains an Accept-Encoding header for gzip, your Apache install may compress that traffic by default and cause your Beacon to be unresponsive or function incorrectly. To overcome this, disable mod_deflate (via a2dismod deflate and add the No Encode ([NE]) flag to your rewrite rules. (Thank you, e0x70i!)"

### Enable SSL support

Ensure the following entries are in the site's config (i.e. `/etc/apache2/available-sites/*.conf`)

    # Enable SSL
    SSLEngine On
    # Enable SSL Proxy
    SSLProxyEngine On
    # Trust Self-Signed Certificates generated by CobaltStrike
    SSLProxyVerify none
    SSLProxyCheckPeerCN off
    SSLProxyCheckPeerName off
    SSLProxyCheckPeerExpire off
### .HTACCESS

If you plan on using mod_rewrite in .htaccess files (instead of the site's config file), you also need to enable the use of `.htaccess` files by changing `AllowOverride None` to `AllowOverride All`. For all websites, edit `/etc/apache2/apache.conf`

    <Directory /var/www/>
        Options FollowSymLinks MultiViews
        AllowOverride All
        Order allow,deny
        allow from all
    </Directory>

Finally, restart apache once more for good measure.

`service apache2 restart`

### Troubleshooting

If you need to troubleshoot redirection rule behavior, enable detailed error tracing in your site's configuration file by adding the following line.

`LogLevel alert rewrite:trace5`

Next, reload apache, and monitor `/var/log/access.log` `/var/log/error.log` to see which rules are matching.

----------------------------------------------


## Final Thoughts

Once redirection is configured and functioning, ensure your C2 servers only allow ingress from the redirector and your trusted IPs (VPN, office ranges, etc).

Consider adding additional redirector protections using GeoIP restrictions (mod_maxmind) and blacklists of bad user agents and IP ranges. Thanks to [@curi0usJack](https://twitter.com/curi0usJack) for the ideas.

## References

- [Joe Vest and Andrew Chiles - cs2modrewrite.py blog post](https://posts.specterops.io/automating-apache-mod-rewrite-and-cobalt-strike-malleable-c2-profiles-d45266ca642)

- [@bluescreenofjeff - Cobalt Strike HTTP C2 Redirectors with Apache mod_rewrite](https://bluescreenofjeff.com/2016-06-28-cobalt-strike-http-c2-redirectors-with-apache-mod_rewrite/)

- [Adam Brown - Resilient Red Team HTTPS Redirection Using Nginx](https://coffeegist.com/security/resilient-red-team-https-redirection-using-nginx/)

- [Apache - Apache mod_rewrite Documentation](http://httpd.apache.org/docs/current/mod/mod_rewrite.html)
