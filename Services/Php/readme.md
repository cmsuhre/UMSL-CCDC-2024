#PHP Hardening

php.ini script in php folder shows ideal configuration for php.ini file
 
TIPS just in case to edit php.ini file: 

**PHP Error Handling**

expose_php              = Off
error_reporting         = E_ALL
display_errors          = Off
display_startup_errors  = Off
log_errors              = On
error_log               = /valid_path/PHP-logs/php_error.log
ignore_repeated_errors  = Off

**PHP general settings**

doc_root                = /path/DocumentRoot/PHP-scripts/
open_basedir            = /path/DocumentRoot/PHP-scripts/
include_path            = /path/PHP-pear/
extension_dir           = /path/PHP-extensions/
mime_magic.magicfile    = /path/PHP-magic.mime
allow_url_fopen         = Off
allow_url_include       = Off
variables_order         = "GPCS"
allow_webdav_methods    = Off
session.gc_maxlifetime  = 600

**PHP file upload handling**

file_uploads            = On
upload_tmp_dir          = /path/PHP-uploads/
upload_max_filesize     = 2M
max_file_uploads        = 2

If your application is not using file uploads, and say the only data the user will enter / upload is forms that do not require any document attachments, file_uploads should be turned Off.

**PHP executable handling**

enable_dl               = Off
disable_functions       = system, exec, shell_exec, passthru, phpinfo, show_source, highlight_file, popen, proc_open, fopen_with_path, dbmopen, dbase_open, putenv, move_uploaded_file, chdir, mkdir, rmdir, chmod, rename, filepro, filepro_rowcount, filepro_retrieve, posix_mkfifo
# see also: http://ir.php.net/features.safe-mode
disable_classes         =

**PHP session handling**

Session settings are some of the MOST important values to concentrate on in configuring. It is a good practice to change session.name to something new.

 session.save_path                = /path/PHP-session/
 session.name                     = myPHPSESSID
 session.auto_start               = Off
 session.use_trans_sid            = 0
 session.cookie_domain            = full.qualified.domain.name
 #session.cookie_path             = /application/path/
 session.use_strict_mode          = 1
 session.use_cookies              = 1
 session.use_only_cookies         = 1
 session.cookie_lifetime          = 14400 # 4 hours
 session.cookie_secure            = 1
 session.cookie_httponly          = 1
 session.cookie_samesite          = Strict
 session.cache_expire             = 30
 session.sid_length               = 256
 session.sid_bits_per_character   = 6 # PHP 7.2+
 session.hash_function            = 1 # PHP 7.0-7.1
 session.hash_bits_per_character  = 6 # PHP 7.0-7.1

**Some more security paranoid checks**

session.referer_check   = /application/path
memory_limit            = 50M
post_max_size           = 20M
max_execution_time      = 60
report_memleaks         = On
track_errors            = Off
html_errors             = Off

