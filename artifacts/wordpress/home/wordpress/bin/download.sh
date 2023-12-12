#!/bin/sh
set -e
BIN_DIR=${HOME}/bin
if [ ! -f $BIN_DIR/wp ]; then
	echo "Downloading wp-cli..."
	curl https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar > $BIN_DIR/wp-cli.phar
	chmod 755 $BIN_DIR/wp-cli.phar
	ln -sf wp-cli.phar $BIN_DIR/wp
fi

DOCUMENT_ROOT=${HOME}/sites/default
mkdir -p $DOCUMENT_ROOT
echo "Setting up WordPress"
wp --path=$DOCUMENT_ROOT core download --locale=ja
wp --path=$DOCUMENT_ROOT config create --dbname=wordpress --dbuser=wordpress --dbcharset=utf8mb4 --dbcollate=utf8_general_ci

echo "Run "
echo "  wp --path=$DOCUMENT_ROOT core install --url='<URL>' --title='<TITLE>' --admin_user='admin' --admin_password='<PASSWORD>' --admin_email='<EMAIL>'"
echo "to complete WordPress installation."

