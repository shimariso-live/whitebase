<?php
putenv('TTRSS_DB_TYPE=mysql');
putenv('TTRSS_DB_HOST=localhost');
putenv('TTRSS_DB_NAME=tt-rss');
putenv('TTRSS_DB_USER=tt-rss');
putenv('TTRSS_DB_PASS=');
putenv('TTRSS_DB_PORT=3306');
putenv('TTRSS_SELF_URL_PATH=' . ($_SERVER["HTTPS"]? 'https://' : 'http://') . $_SERVER["SERVER_NAME"]);
