#! /bin/sh

echo "user_pref(\"security.tls.version.fallback-limit\", 3);\nuser_pref(\"security.tls.version.max\", 3);" >> obj-x86_64-pc-linux-gnu/tmp/profile-default/prefs.js
