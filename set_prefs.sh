#! /bin/sh

# Disable TLS 1.3
echo "user_pref(\"security.tls.version.fallback-limit\", 3);\nuser_pref(\"security.tls.version.max\", 3);\n" >> obj-x86_64-pc-linux-gnu/tmp/profile-default/prefs.js

#Disable HTTP/2.0
echo "user_pref(\"network.http.spdy.enabled.http2\", false);\n" >> obj-x86_64-pc-linux-gnu/tmp/profile-default/prefs.js
