/*
   +----------------------------------------------------------------------+
   | PHP version 4.0                                                      |
   +----------------------------------------------------------------------+
   | Copyright (c) 1997, 1998, 1999 The PHP Group                         |
   +----------------------------------------------------------------------+
   | This source file is subject to version 2.0 of the PHP license,       |
   | that is bundled with this package in the file LICENSE, and is        |
   | available at through the world-wide-web at                           |
   | http://www.php.net/license/2_0.txt.                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Authors: Sascha Schumann <ss@schumann.cx>                            |
   |          Andrei Zmievski <andrei@ispi.net>                           |
   +----------------------------------------------------------------------+
 */

#if !(WIN32|WINNT)
#include <sys/time.h>
#else
#include "win32/time.h"
#endif

#include <sys/stat.h>
#include <fcntl.h>

#include "php.h"
#include "php_ini.h"
#include "SAPI.h"

#include "php_session.h"
#include "ext/standard/md5.h"
#include "ext/standard/php_var.h"
#include "ext/standard/datetime.h"
#include "ext/standard/php_lcg.h"
#include "ext/standard/url_scanner.h"
#include "ext/standard/php_rand.h"                   /* for RAND_MAX */

#ifdef ZTS
int ps_globals_id;
#else
static php_ps_globals ps_globals;
#endif

#include "modules.c"

function_entry session_functions[] = {
	PHP_FE(session_name, NULL)
	PHP_FE(session_module_name, NULL)
	PHP_FE(session_save_path, NULL)
	PHP_FE(session_id, NULL)
	PHP_FE(session_decode, NULL)
	PHP_FE(session_register, NULL)
	PHP_FE(session_unregister, NULL)
	PHP_FE(session_is_registered, NULL)
	PHP_FE(session_encode, NULL)
	PHP_FE(session_start, NULL)
	PHP_FE(session_destroy, NULL)
	PHP_FE(session_unset, NULL)
	PHP_FE(session_set_save_handler, NULL)
	{0}
};

PHP_INI_BEGIN()
	PHP_INI_ENTRY("session.save_path", "/tmp", PHP_INI_ALL, NULL)
	PHP_INI_ENTRY("session.name", "PHPSESSID", PHP_INI_ALL, NULL)
	PHP_INI_ENTRY("session.save_handler", "files", PHP_INI_ALL, NULL)
	PHP_INI_ENTRY("session.auto_start", "0", PHP_INI_ALL, NULL)
	PHP_INI_ENTRY("session.gc_probability", "1", PHP_INI_ALL, NULL)
	PHP_INI_ENTRY("session.gc_maxlifetime", "1440", PHP_INI_ALL, NULL)
	PHP_INI_ENTRY("session.serialize_handler", "php", PHP_INI_ALL, NULL)
	PHP_INI_ENTRY("session.cookie_lifetime", "0", PHP_INI_ALL, NULL)
	PHP_INI_ENTRY("session.cookie_path", "/", PHP_INI_ALL, NULL)
	PHP_INI_ENTRY("session.cookie_domain", "", PHP_INI_ALL, NULL)
	PHP_INI_ENTRY("session.use_cookies", "1", PHP_INI_ALL, NULL)
	PHP_INI_ENTRY("session.referer_check", "", PHP_INI_ALL, NULL)
	PHP_INI_ENTRY("session.entropy_file", "", PHP_INI_ALL, NULL)
	PHP_INI_ENTRY("session.entropy_length", "0", PHP_INI_ALL, NULL)
	PHP_INI_ENTRY("session.cache_limiter", "nocache", PHP_INI_ALL, NULL)
	PHP_INI_ENTRY("session.cache_expire", "180", PHP_INI_ALL, NULL)
	/* Commented out until future discussion */
	/* PHP_INI_ENTRY("session.encode_sources", "globals,track", PHP_INI_ALL, NULL) */
PHP_INI_END()

PS_SERIALIZER_FUNCS(php);
#ifdef WDDX_SERIALIZER
PS_SERIALIZER_FUNCS(wddx);
#endif


const static ps_serializer ps_serializers[] = {
#ifdef WDDX_SERIALIZER
	PS_SERIALIZER_ENTRY(wddx),
#endif
	PS_SERIALIZER_ENTRY(php),
	{0}
};

PHP_MINIT_FUNCTION(session);
PHP_RINIT_FUNCTION(session);
PHP_MSHUTDOWN_FUNCTION(session);
PHP_RSHUTDOWN_FUNCTION(session);
PHP_MINFO_FUNCTION(session);

static void php_rinit_session_globals(PSLS_D);
static void php_rshutdown_session_globals(PSLS_D);

zend_module_entry session_module_entry = {
	"Session Management",
	session_functions,
	PHP_MINIT(session), PHP_MSHUTDOWN(session),
	PHP_RINIT(session), PHP_RSHUTDOWN(session),
	PHP_MINFO(session),
	STANDARD_MODULE_PROPERTIES,
};

typedef struct {
	char *name;
	void (*func)(PSLS_D);
} php_session_cache_limiter;

#define CACHE_LIMITER_FUNC(name) void _php_cache_limiter_##name(PSLS_D)
#define CACHE_LIMITER(name) { #name, _php_cache_limiter_##name },

#define ADD_COOKIE(a) sapi_add_header(estrdup(a), strlen(a));

#define STR_CAT(P,S,I) {\
	pval *__p = (P);\
		ulong __i = __p->value.str.len;\
		__p->value.str.len += (I);\
		if (__p->value.str.val) {\
			__p->value.str.val = (char *)erealloc(__p->value.str.val, __p->value.str.len + 1);\
		} else {\
			__p->value.str.val = emalloc(__p->value.str.len + 1);\
				*__p->value.str.val = 0;\
		}\
	strcat(__p->value.str.val + __i, (S));\
}

#define MAX_STR 512
#define STD_FMT "%s|"
#define NOTFOUND_FMT "!%s|"

#define PS_ADD_VARL(name,namelen) \
	zend_hash_update(&PS(vars), name, namelen + 1, 0, 0, NULL)

#define PS_ADD_VAR(name) PS_ADD_VARL(name, strlen(name))

#define PS_DEL_VARL(name,namelen) \
	zend_hash_del(&PS(vars), name, namelen + 1);

#define PS_DEL_VAR(name) PS_DEL_VARL(name, strlen(name))

#define ENCODE_VARS 											\
	char *key;													\
	ulong num_key;												\
	zval **struc;												\
	ELS_FETCH()

#define ENCODE_LOOP(code)										\
	for(zend_hash_internal_pointer_reset(&PS(vars));			\
			zend_hash_get_current_key(&PS(vars), &key, &num_key) == HASH_KEY_IS_STRING; \
			zend_hash_move_forward(&PS(vars))) {				\
		if(php_get_session_var(key, strlen(key), &struc PSLS_CC ELS_CC) == SUCCESS) { \
			code;		 										\
		} 														\
		efree(key);												\
	}

static void php_set_session_var(char *name, size_t namelen,
								zval *state_val PSLS_DC)
{
	zval *state_val_copy;
	PLS_FETCH();
	ELS_FETCH();

	ALLOC_ZVAL(state_val_copy);
	*state_val_copy = *state_val;
	zval_copy_ctor(state_val_copy);
	state_val_copy->refcount = 0;

	if (PG(gpc_globals) && PG(track_vars)) {
		zend_set_hash_symbol(state_val_copy, name, namelen, 1, 2, PS(http_state_vars)->value.ht, &EG(symbol_table));
	} else {
		if (PG(gpc_globals)) {
			zend_set_hash_symbol(state_val_copy, name, namelen, 0, 1, &EG(symbol_table));
		}

		if (PG(track_vars)) {
			zend_set_hash_symbol(state_val_copy, name, namelen, 0, 1, PS(http_state_vars)->value.ht);
		}
	}
}

static int php_get_session_var(char *name, size_t namelen, zval ***state_var PSLS_DC ELS_DC)
{
	return zend_hash_find(&EG(symbol_table), name, namelen + 1, (void **)state_var);
}

PS_SERIALIZER_ENCODE_FUNC(php)
{
	zval *buf;
	char strbuf[MAX_STR + 1];
	ENCODE_VARS;

	buf = ecalloc(sizeof(*buf), 1);
	buf->type = IS_STRING;
	buf->refcount++;

	ENCODE_LOOP(
			snprintf(strbuf, MAX_STR, STD_FMT, key);
			STR_CAT(buf, strbuf, strlen(strbuf));
			php_var_serialize(buf, struc);
		} else {
			snprintf(strbuf, MAX_STR, NOTFOUND_FMT, key);
			STR_CAT(buf, strbuf, strlen(strbuf));
	);

	if(newlen) *newlen = buf->value.str.len;
	*newstr = buf->value.str.val;
	efree(buf);

	return SUCCESS;
}

PS_SERIALIZER_DECODE_FUNC(php)	
{
	const char *p, *q;
	char *name;
	const char *endptr = val + vallen;
	zval *current;
	int namelen;
	int has_value;

	current = (zval *) ecalloc(sizeof(zval), 1);
	for(p = q = val; (p < endptr) && (q = strchr(p, '|')); p = q) {
		if(p[0] == '!') {
			p++;
			has_value = 0;
		} else {
			has_value = 1;
		}
		
		namelen = q - p;
		name = estrndup(p, namelen);
		q++;
		
		if(has_value) {
			if(php_var_unserialize(&current, &q, endptr)) {
				php_set_session_var(name, namelen, current PSLS_CC);
				zval_dtor(current);
			}
		}
		PS_ADD_VAR(name);
		efree(name);
	}
	efree(current);

	return SUCCESS;
}

#ifdef WDDX_SERIALIZER

PS_SERIALIZER_ENCODE_FUNC(wddx)
{
	wddx_packet *packet;
	ENCODE_VARS;

	packet = _php_wddx_constructor();
	if(!packet) return FAILURE;

	_php_wddx_packet_start(packet, NULL);
	_php_wddx_add_chunk(packet, WDDX_STRUCT_S);
	
	ENCODE_LOOP(
		_php_wddx_serialize_var(packet, *struc, key);
	);
	
	_php_wddx_add_chunk(packet, WDDX_STRUCT_E);
	_php_wddx_packet_end(packet);
	*newstr = _php_wddx_gather(packet);
	_php_wddx_destructor(packet);
	
	if(newlen) *newlen = strlen(*newstr);

	return SUCCESS;
}

PS_SERIALIZER_DECODE_FUNC(wddx)
{
	zval *retval;
	zval **ent;
	char *key;
	char tmp[128];
	ulong idx;
	int hash_type;
	int dofree = 1;

	if(vallen == 0) return FAILURE;
	
	MAKE_STD_ZVAL(retval);

	_php_wddx_deserialize_ex((char *)val, vallen, retval);

	for(zend_hash_internal_pointer_reset(retval->value.ht);
			zend_hash_get_current_data(retval->value.ht, (void **) &ent) == SUCCESS;
			zend_hash_move_forward(retval->value.ht)) {
		hash_type = zend_hash_get_current_key(retval->value.ht, &key, &idx);

		switch(hash_type) {
			case HASH_KEY_IS_LONG:
				sprintf(tmp, "%ld", idx);
				key = tmp;
				dofree = 0;
			case HASH_KEY_IS_STRING:
				php_set_session_var(key, strlen(key), *ent PSLS_CC);
				PS_ADD_VAR(key);
				if(dofree) efree(key);
				dofree = 1;
		}
	}

	zval_dtor(retval);
	efree(retval);

	return SUCCESS;
}

#endif

static void php_session_track_init(void)
{
	PSLS_FETCH();
	ELS_FETCH();

	if (zend_hash_find(&EG(symbol_table), "HTTP_STATE_VARS", sizeof("HTTP_STATE_VARS"),
					   (void **)&PS(http_state_vars)) == FAILURE || PS(http_state_vars)->type != IS_ARRAY) {
		MAKE_STD_ZVAL(PS(http_state_vars));
		array_init(PS(http_state_vars));
		ZEND_SET_GLOBAL_VAR_WITH_LENGTH("HTTP_STATE_VARS", sizeof("HTTP_STATE_VARS"), PS(http_state_vars), 1, 0);
	} else
		zend_hash_clean(PS(http_state_vars)->value.ht);
}

static char *_php_session_encode(int *newlen PSLS_DC)
{
	char *ret = NULL;

	if(PS(serializer)->encode(&ret, newlen PSLS_CC) == FAILURE) {
		ret = NULL;
	}

	return ret;
}

static void _php_session_decode(const char *val, int vallen PSLS_DC)
{
	PLS_FETCH();

	if (PG(track_vars))
		php_session_track_init();
	PS(serializer)->decode(val, vallen PSLS_CC);
}

static char *_php_create_id(int *newlen PSLS_DC)
{
	PHP3_MD5_CTX context;
	unsigned char digest[16];
	char buf[256];
	struct timeval tv;
	int i;

	gettimeofday(&tv, NULL);
	PHP3_MD5Init(&context);
	
	sprintf(buf, "%ld%ld%0.8f", tv.tv_sec, tv.tv_usec, php_combined_lcg() * 10);
	PHP3_MD5Update(&context, buf, strlen(buf));

	if(PS(entropy_length) > 0) {
		int fd;

		fd = open(PS(entropy_file), O_RDONLY);
		if(fd >= 0) {
			char *p;
			int n;
			
			p = emalloc(PS(entropy_length));
			n = read(fd, p, PS(entropy_length));
			if(n > 0) {
				PHP3_MD5Update(&context, p, n);
			}
			efree(p);
			close(fd);
		}
	}

	PHP3_MD5Final(digest, &context);

	for(i = 0; i < 16; i++)
		sprintf(buf + (i << 1), "%02x", digest[i]);
	buf[i << 1] = '\0';
	
	if(newlen) *newlen = i << 1;
	return estrdup(buf);
}

static void _php_session_initialize(PSLS_D)
{
	char *val;
	int vallen;
	
	if(PS(mod)->open(&PS(mod_data), PS(save_path), PS(session_name)) == FAILURE) {
		php_error(E_ERROR, "failed to initialize session module");
		return;
	}
	if(PS(mod)->read(&PS(mod_data), PS(id), &val, &vallen) == SUCCESS) {
		_php_session_decode(val, vallen PSLS_CC);
		efree(val);
	}
}

static void _php_session_save_current_state(PSLS_D)
{
	char *val;
	int vallen;
	
	val = _php_session_encode(&vallen PSLS_CC);
	if(val) {
		PS(mod)->write(&PS(mod_data), PS(id), val, vallen);
		efree(val);
	} else {
		PS(mod)->write(&PS(mod_data), PS(id), "", 0);
	}
	PS(mod)->close(&PS(mod_data));
}

static char *month_names[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static char *week_days[] = {
	"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"
};

static void strcat_gmt(char *ubuf, time_t *when)
{
	char buf[MAX_STR];
	struct tm tm;
	
	gmtime_r(when, &tm);
	
	/* we know all components, thus it is safe to use sprintf */
	sprintf(buf, "%s, %d %s %d %02d:%02d:%02d GMT", week_days[tm.tm_wday], tm.tm_mday, month_names[tm.tm_mon], tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
	strcat(ubuf, buf);
}

static void last_modified(void)
{
	char *path;
	struct stat sb;
	char buf[MAX_STR + 1];
	SLS_FETCH();

	path = SG(request_info).path_translated;
	if (path) {
		if (stat(path, &sb) == -1) {
			return;
		}

		strcpy(buf, "Last-Modified: ");
		strcat_gmt(buf, &sb.st_mtime);
		ADD_COOKIE(buf);
	}
}

CACHE_LIMITER_FUNC(public)
{
	char buf[MAX_STR + 1];
	time_t now;
	
	time(&now);
	now += PS(cache_expire) * 60;
	strcpy(buf, "Expires: ");
	strcat_gmt(buf, &now);
	ADD_COOKIE(buf);
	
	sprintf(buf, "Cache-Control: public, max-age=%d", PS(cache_expire) * 60);
	ADD_COOKIE(buf);
	
	last_modified();
}
	
CACHE_LIMITER_FUNC(private)
{
	char buf[MAX_STR + 1];
	
	ADD_COOKIE("Expires: Thu, 19 Nov 1981 08:52:00 GMT");
	sprintf(buf, "Cache-Control: private, max-age=%d", PS(cache_expire) * 60);
	ADD_COOKIE(buf);

	last_modified();
}

CACHE_LIMITER_FUNC(nocache)
{
	ADD_COOKIE("Expires: Thu, 19 Nov 1981 08:52:00 GMT");
	/* For HTTP/1.1 conforming clients */
	ADD_COOKIE("Cache-Control: no-cache");
	/* For HTTP/1.0 conforming clients */
	ADD_COOKIE("Pragma: no-cache");
}

static php_session_cache_limiter php_session_cache_limiters[] = {
	CACHE_LIMITER(public)
	CACHE_LIMITER(private)
	CACHE_LIMITER(nocache)
	{0}
};
	

static void _php_session_cache_limiter(PSLS_D)
{
	php_session_cache_limiter *lim;

	for (lim = php_session_cache_limiters; lim->name; lim++) {
		if (!strcasecmp(lim->name, PS(cache_limiter))) {
			lim->func(PSLS_C);
			break;
		}
	}
}

#define COOKIE_FMT 		"Set-Cookie: %s=%s"
#define COOKIE_EXPIRES	"; expires="
#define COOKIE_PATH		"; path="
#define COOKIE_DOMAIN	"; domain="

static void _php_session_send_cookie(PSLS_D)
{
	int len;
	int pathlen;
	int domainlen;
	char *cookie;
	char *date_fmt = NULL;

	len = strlen(PS(session_name)) + strlen(PS(id)) + sizeof(COOKIE_FMT);
	if (PS(cookie_lifetime) > 0) {
		date_fmt = php_std_date(time(NULL) + PS(cookie_lifetime));
		len += sizeof(COOKIE_EXPIRES) + strlen(date_fmt);
	}

	pathlen = strlen(PS(cookie_path));
	if (pathlen > 0) {
		len += pathlen + sizeof(COOKIE_PATH);
	}

	domainlen = strlen(PS(cookie_domain));
	if (domainlen > 0) {
		len += domainlen + sizeof(COOKIE_DOMAIN);
	}
	
	cookie = ecalloc(len + 1, 1);
	
	len = snprintf(cookie, len, COOKIE_FMT, PS(session_name), PS(id));
	if (PS(cookie_lifetime) > 0) {
		strcat(cookie, COOKIE_EXPIRES);
		strcat(cookie, date_fmt);
		len += strlen(COOKIE_EXPIRES) + strlen(date_fmt);
		efree(date_fmt);
	}
	
	if (pathlen > 0) {
		strcat(cookie, COOKIE_PATH);
		strcat(cookie, PS(cookie_path));
	}

	if (domainlen > 0) {
		strcat(cookie, COOKIE_DOMAIN);
		strcat(cookie, PS(cookie_domain));
	}

	sapi_add_header(cookie, len);
}

static ps_module *_php_find_ps_module(char *name PSLS_DC)
{
	ps_module *ret = NULL;
	ps_module **mod;
	ps_module **end = ps_modules + (sizeof(ps_modules)/sizeof(ps_module*));

	for(mod = ps_modules; mod < end; mod++) {
		if(*mod && !strcasecmp(name, (*mod)->name)) {
			ret = *mod;
			break;
		}
	}
	
	return ret;
}

static const ps_serializer *_php_find_ps_serializer(char *name PSLS_DC)
{
	const ps_serializer *ret = NULL;
	const ps_serializer *mod;

	for(mod = ps_serializers; mod->name; mod++) {
		if(!strcasecmp(name, mod->name)) {
			ret = mod;
			break;
		}
	}

	return ret;
}

#define PPID2SID \
		convert_to_string((*ppid)); \
		PS(id) = estrndup((*ppid)->value.str.val, (*ppid)->value.str.len)

static void _php_session_start(PSLS_D)
{
	pval **ppid;
	pval **data;
	char *p;
	int send_cookie = 1;
	int define_sid = 1;
	zend_bool gpc_globals;
	zend_bool track_vars;
	int module_number = PS(module_number);
	int nrand;
	int lensess;
	ELS_FETCH();

	if (PS(nr_open_sessions) != 0) return;

	lensess = strlen(PS(session_name));
	
	gpc_globals = INI_BOOL("gpc_globals");
	track_vars = INI_BOOL("track_vars");

	if (!gpc_globals && !track_vars) {
		php_error(E_ERROR, "The sessions module will not work, if you have disabled track_vars and gpc_globals. Enable at least one of them.");
		return;
	}

	if (!track_vars && PS(use_cookies)) {
		php_error(E_NOTICE, "Because track_vars are disabled, the session module will not be able to determine whether the user has sent a cookie. SID will always be defined.");
	}
	
	/*
	 * If our only resource is the global symbol_table, then check it.
	 * If track_vars are enabled, we prefer these, because they are more
	 * reliable, and we always know whether the user has accepted the 
	 * cookie.
	 */
	
	if (gpc_globals && 
			!track_vars &&
			!PS(id) &&
			zend_hash_find(&EG(symbol_table), PS(session_name),
				lensess + 1, (void **) &ppid) == SUCCESS) {
		PPID2SID;
		send_cookie = 0;
	}
	
	/*
     * Now check the track_vars. Cookies are preferred, because initially
	 * cookie and get variables will be available. 
	 */

	if (!PS(id) && track_vars) {
		if (zend_hash_find(&EG(symbol_table), "HTTP_COOKIE_VARS",
					sizeof("HTTP_COOKIE_VARS"), (void **) &data) == SUCCESS &&
				(*data)->type == IS_ARRAY &&
				zend_hash_find((*data)->value.ht, PS(session_name),
					lensess + 1, (void **) &ppid) == SUCCESS) {
			PPID2SID;
			define_sid = 0;
			send_cookie = 0;
		}

		if (!PS(id) &&
				zend_hash_find(&EG(symbol_table), "HTTP_GET_VARS",
					sizeof("HTTP_GET_VARS"), (void **) &data) == SUCCESS &&
				(*data)->type == IS_ARRAY &&
				zend_hash_find((*data)->value.ht, PS(session_name),
					lensess + 1, (void **) &ppid) == SUCCESS) {
			PPID2SID;
		}

		if (!PS(id) &&
				zend_hash_find(&EG(symbol_table), "HTTP_POST_VARS",
					sizeof("HTTP_POST_VARS"), (void **) &data) == SUCCESS &&
				(*data)->type == IS_ARRAY &&
				zend_hash_find((*data)->value.ht, PS(session_name),
					lensess + 1, (void **) &ppid) == SUCCESS) {
			PPID2SID;
		}
	}

	/* check the REQUEST_URI symbol for a string of the form
	   '<session-name>=<session-id>' to allow URLs of the form
       http://yoursite/<session-name>=<session-id>/script.php */

	if(!PS(id) &&
			zend_hash_find(&EG(symbol_table), "REQUEST_URI",
				sizeof("REQUEST_URI"), (void **) &data) == SUCCESS &&
			(*data)->type == IS_STRING &&
			(p = strstr((*data)->value.str.val, PS(session_name))) &&
			p[lensess] == '=') {
		char *q;

		p += lensess + 1;
		if((q = strpbrk(p, "/?\\")))
			PS(id) = estrndup(p, q - p);
	}

	/* check whether the current request was referred to by
	   an external site which invalidates the previously found id */
	
	if(PS(id) &&
			PS(extern_referer_chk)[0] != '\0' &&
			zend_hash_find(&EG(symbol_table), "HTTP_REFERER",
				sizeof("HTTP_REFERER"), (void **) &data) == SUCCESS &&
			(*data)->type == IS_STRING &&
			(*data)->value.str.len != 0 &&
			strstr((*data)->value.str.val, PS(extern_referer_chk)) == NULL) {
		efree(PS(id));
		PS(id) = NULL;
		send_cookie = 1;
		define_sid = 1;
	}
	
	if(!PS(id)) {
		PS(id) = _php_create_id(NULL PSLS_CC);
	}
	
	if(!PS(use_cookies) && send_cookie) {
		define_sid = 1;
		send_cookie = 0;
	}
	
	if(send_cookie) {
		_php_session_send_cookie(PSLS_C);
	}
	
	if(define_sid) {
		char *buf;

		buf = emalloc(strlen(PS(session_name)) + strlen(PS(id)) + 5);
		sprintf(buf, "%s=%s", PS(session_name), PS(id));
		REGISTER_STRING_CONSTANT("SID", buf, 0);
	} else {
		REGISTER_STRING_CONSTANT("SID", empty_string, 0);
	}
	PS(define_sid) = define_sid;

	PS(nr_open_sessions)++;

	_php_session_cache_limiter(PSLS_C);
	_php_session_initialize(PSLS_C);

	if(PS(mod_data) && PS(gc_probability) > 0) {
		srand(time(NULL));
		nrand = (int) (100.0*rand()/RAND_MAX);
		if(nrand < PS(gc_probability))
			PS(mod)->gc(&PS(mod_data), PS(gc_maxlifetime));
	}
}

static void _php_session_destroy(PSLS_D)
{
	if(PS(nr_open_sessions) == 0)
	{
		php_error(E_WARNING, "Trying to destroy uninitialized session");
		return;
	}

	PS(mod)->destroy(&PS(mod_data), PS(id));
	php_rshutdown_session_globals(PSLS_C);
	php_rinit_session_globals(PSLS_C);
}

/* {{{ proto string session_name([string newname])
   return the current session name. if newname is given, the session name is replaced with newname */
PHP_FUNCTION(session_name)
{
	pval **p_name;
	int ac = ARG_COUNT(ht);
	char *old;
	PSLS_FETCH();

	old = estrdup(PS(session_name));

	if(ac < 0 || ac > 1 || zend_get_parameters_ex(ac, &p_name) == FAILURE) {
		WRONG_PARAM_COUNT;
	}

	if(ac == 1) {
		convert_to_string_ex(p_name);
		efree(PS(session_name));
		PS(session_name) = estrndup((*p_name)->value.str.val, (*p_name)->value.str.len);
	}
	
	RETVAL_STRING(old, 0);
}
/* }}} */

/* {{{ proto string session_module_name([string newname])
   return the current module name used for accessing session data. if newname is given, the module name is replaced with newname */
PHP_FUNCTION(session_module_name)
{
	pval **p_name;
	int ac = ARG_COUNT(ht);
	char *old;
	PSLS_FETCH();

	old = estrdup(PS(mod)->name);

	if(ac < 0 || ac > 1 || zend_get_parameters_ex(ac, &p_name) == FAILURE) {
		WRONG_PARAM_COUNT;
	}

	if(ac == 1) {
		ps_module *tempmod;

		convert_to_string_ex(p_name);
		tempmod = _php_find_ps_module((*p_name)->value.str.val PSLS_CC);
		if(tempmod) {
			if(PS(mod_data))
				PS(mod)->close(&PS(mod_data));
			PS(mod_data) = tempmod;
		} else {
			efree(old);
			php_error(E_ERROR, "Cannot find named PHP session module (%s)",
					(*p_name)->value.str.val);
			RETURN_FALSE;
		}
	}

	RETVAL_STRING(old, 0);
}
/* }}} */

/* {{{ proto void session_set_save_handler(string open, string close, string read, string write, string destroy, string gc)
   sets user-level functions */
PHP_FUNCTION(session_set_save_handler)
{
	zval **args[6];
	int i;
	ps_user *mdata;
	PSLS_FETCH();

	if(ARG_COUNT(ht) != 6 || zend_get_parameters_array_ex(6, args) == FAILURE) {
		WRONG_PARAM_COUNT;
	}
	
	if(PS(nr_open_sessions) > 0) {
		RETURN_FALSE;
	}
	
	PS(mod) = _php_find_ps_module("user" PSLS_CC);

	mdata = emalloc(sizeof *mdata);
	
	for(i = 0; i < 6; i++) {
		convert_to_string_ex(args[i]);
		mdata->names[i] = estrdup((*args[i])->value.str.val);
	}
	
	PS(mod_data) = (void *) mdata;
	
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto string session_save_path([string newname])
   return the current save path passed to module_name. if newname is given, the save path is replaced with newname */
PHP_FUNCTION(session_save_path)
{
	pval **p_name;
	int ac = ARG_COUNT(ht);
	char *old;
	PSLS_FETCH();

	old = estrdup(PS(save_path));

	if(ac < 0 || ac > 1 || zend_get_parameters_ex(ac, &p_name) == FAILURE) {
		WRONG_PARAM_COUNT;
	}

	if(ac == 1) {
		convert_to_string_ex(p_name);
		efree(PS(save_path));
		PS(save_path) = estrndup((*p_name)->value.str.val, (*p_name)->value.str.len);
	}
	
	RETVAL_STRING(old, 0);
}
/* }}} */

/* {{{ proto string session_id([string newid])
   return the current session id. if newid is given, the session id is replaced with newid */
PHP_FUNCTION(session_id)
{
	pval **p_name;
	int ac = ARG_COUNT(ht);
	char *old = empty_string;
	PSLS_FETCH();

	if(PS(id))
		old = estrdup(PS(id));

	if(ac < 0 || ac > 1 || zend_get_parameters_ex(ac, &p_name) == FAILURE) {
		WRONG_PARAM_COUNT;
	}

	if(ac == 1) {
		convert_to_string_ex(p_name);
		if(PS(id)) efree(PS(id));
		PS(id) = estrndup((*p_name)->value.str.val, (*p_name)->value.str.len);
	}
	
	RETVAL_STRING(old, 0);
}
/* }}} */


/* {{{ static void php_register_var(zval** entry PSLS_DC PLS_DC) */
static void php_register_var(zval** entry PSLS_DC PLS_DC)
{
	zval**   value;
	
	if ((*entry)->type == IS_ARRAY) {
		zend_hash_internal_pointer_reset((*entry)->value.ht);

		while(zend_hash_get_current_data((*entry)->value.ht, (void**)&value) == SUCCESS) {
			php_register_var(value PSLS_CC PLS_CC);
			zend_hash_move_forward((*entry)->value.ht);
		}
	} else if (!PG(track_vars) || strcmp((*entry)->value.str.val, "HTTP_STATE_VARS") != 0) {
		convert_to_string_ex(entry);
		
		PS_ADD_VARL((*entry)->value.str.val, (*entry)->value.str.len);
	}
}
/* }}} */


/* {{{ proto bool session_register(string var_name | array var_names [, ... ])
   adds varname(s) to the list of variables which are freezed at the session end */
PHP_FUNCTION(session_register)
{
	zval***  args;
	int      argc = ARG_COUNT(ht);
	int      i;
	PSLS_FETCH();
	PLS_FETCH();

	if (argc <= 0) {
		RETURN_FALSE;
	} else
		args = (zval ***)emalloc(argc * sizeof(zval **));
	
	if (zend_get_parameters_array_ex(argc, args) == FAILURE) {
		efree(args);
		WRONG_PARAM_COUNT;
	}

	if(!PS(nr_open_sessions)) _php_session_start(PSLS_C);

	for (i=0; i<argc; i++)
	{
		if ((*args[i])->type == IS_ARRAY) {
			SEPARATE_ZVAL(args[i]);
		}
		php_register_var(args[i] PSLS_CC PLS_CC);
	}	
	
	efree(args);
	
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool session_unregister(string varname)
   removes varname from the list of variables which are freezed at the session end */
PHP_FUNCTION(session_unregister)
{
	pval **p_name;
	int ac = ARG_COUNT(ht);
	PSLS_FETCH();

	if(ac != 1 || zend_get_parameters_ex(ac, &p_name) == FAILURE) {
		WRONG_PARAM_COUNT;
	}
	
	convert_to_string_ex(p_name);
	
	PS_DEL_VAR((*p_name)->value.str.val);

	RETURN_TRUE;
}
/* }}} */


/* {{{ proto bool session_is_registered(string varname)
   checks if a variable is registered in session */
PHP_FUNCTION(session_is_registered)
{
	pval **p_name;
	pval *p_var;
	int ac = ARG_COUNT(ht);
	PSLS_FETCH();

	if(ac != 1 || zend_get_parameters_ex(ac, &p_name) == FAILURE) {
		WRONG_PARAM_COUNT;
	}
	
	convert_to_string_ex(p_name);
	
	if (zend_hash_find(&PS(vars), (*p_name)->value.str.val, (*p_name)->value.str.len+1,
					   (void **)&p_var) == SUCCESS) {
		RETURN_TRUE;
	} else {
		RETURN_FALSE;
	}
}
/* }}} */


/* {{{ proto string session_encode()
   serializes the current setup and returns the serialized representation */
PHP_FUNCTION(session_encode)
{
	int len;
	char *enc;
	PSLS_FETCH();

	enc = _php_session_encode(&len PSLS_CC);
	RETVAL_STRINGL(enc, len, 0);
}
/* }}} */

/* {{{ proto session_decode(string data)
   deserializes data and reinitializes the variables */
PHP_FUNCTION(session_decode)
{
	pval **str;
	PSLS_FETCH();

	if(ARG_COUNT(ht) != 1 || zend_get_parameters_ex(1, &str) == FAILURE) {
		WRONG_PARAM_COUNT;
	}

	convert_to_string_ex(str);

	_php_session_decode((*str)->value.str.val, (*str)->value.str.len PSLS_CC);
}
/* }}} */

/* {{{ proto session_start()
   Begin session - reinitializes freezed variables, registers browsers etc */
PHP_FUNCTION(session_start)
{
	PSLS_FETCH();

	_php_session_start(PSLS_C);

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto session_destroy()
   Destroy the current session and all data associated with it */
PHP_FUNCTION(session_destroy)
{
	PSLS_FETCH();
		
	_php_session_destroy(PSLS_C);
}
/* }}} */

#ifdef TRANS_SID
void session_adapt_uris(const char *src, uint srclen, char **new, uint *newlen)
{
	char *data;
	size_t len;
	char buf[512];
	PSLS_FETCH();

	if(PS(define_sid) && PS(nr_open_sessions) > 0) {
		snprintf(buf, sizeof(buf), "%s=%s", PS(session_name), PS(id));
		data = url_adapt(src, srclen, buf, &len);
		*new = data;
		*newlen = len;
	}
}
#endif

/* {{{ proto session_unset()
   Unset all registered variables */
PHP_FUNCTION(session_unset)
{
	zval	**tmp;
	char	 *variable;
	ulong     num_key;
	ELS_FETCH();
	PSLS_FETCH();
	
	for(zend_hash_internal_pointer_reset(&PS(vars));
			zend_hash_get_current_key(&PS(vars), &variable, &num_key) == HASH_KEY_IS_STRING;
			zend_hash_move_forward(&PS(vars))) {
		if(zend_hash_find(&EG(symbol_table), variable, strlen(variable) + 1, (void **) &tmp)
				== SUCCESS) {
			zend_hash_del(&EG(symbol_table), variable, strlen(variable) + 1);
		}
		efree(variable);
	}
}
/* }}} */

static void php_rinit_session_globals(PSLS_D)
{
	PS(mod) = _php_find_ps_module(INI_STR("session.save_handler") PSLS_CC);
	PS(serializer) = \
		_php_find_ps_serializer(INI_STR("session.serialize_handler") PSLS_CC);
		
	zend_hash_init(&PS(vars), 0, NULL, NULL, 0);
	PS(define_sid) = 0;
	PS(use_cookies) = INI_BOOL("session.use_cookies");
	PS(save_path) = estrdup(INI_STR("session.save_path"));
	PS(session_name) = estrdup(INI_STR("session.name"));
	PS(entropy_file) = estrdup(INI_STR("session.entropy_file"));
	PS(entropy_length) = INI_INT("session.entropy_length");
	PS(gc_probability) = INI_INT("session.gc_probability");
	PS(gc_maxlifetime) = INI_INT("session.gc_maxlifetime");
	PS(extern_referer_chk) = estrdup(INI_STR("session.referer_check"));
	PS(id) = NULL;
	PS(cookie_lifetime) = INI_INT("session.cookie_lifetime");
	PS(cookie_path) = estrdup(INI_STR("session.cookie_path"));
	PS(cookie_domain) = estrdup(INI_STR("session.cookie_domain"));
	PS(cache_limiter) = estrdup(INI_STR("session.cache_limiter"));
	PS(cache_expire) = INI_INT("session.cache_expire");
	PS(nr_open_sessions) = 0;
	PS(mod_data) = NULL;
}

static void php_rshutdown_session_globals(PSLS_D)
{
	if(PS(mod_data))
		PS(mod)->close(&PS(mod_data));
	if(PS(entropy_file)) efree(PS(entropy_file));
	if(PS(extern_referer_chk)) efree(PS(extern_referer_chk));
	if(PS(save_path)) efree(PS(save_path));
	if(PS(session_name)) efree(PS(session_name));
	if(PS(id)) efree(PS(id));
	efree(PS(cache_limiter));
	efree(PS(cookie_path));
	efree(PS(cookie_domain));
	zend_hash_destroy(&PS(vars));
}

void _php_session_auto_start(void *data)
{
	PSLS_FETCH();

	_php_session_start(PSLS_C);
}

PHP_RINIT_FUNCTION(session)
{
	PSLS_FETCH();

	php_rinit_session_globals(PSLS_C);

	if(PS(mod) == NULL) {
		/* current status is unusable */
		PS(nr_open_sessions) = -1;
		return SUCCESS;
	}

	if (INI_INT("session.auto_start")) {
		php_register_post_request_startup(_php_session_auto_start, NULL);
	}

	return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(session)
{
	PSLS_FETCH();

	if(PS(nr_open_sessions) > 0) {
		_php_session_save_current_state(PSLS_C);
		PS(nr_open_sessions)--;
	}
	php_rshutdown_session_globals(PSLS_C);
	return SUCCESS;
}

PHP_MINIT_FUNCTION(session)
{
#ifdef ZTS
	php_ps_globals *ps_globals;

	ps_globals_id = ts_allocate_id(sizeof(php_ps_globals), NULL, NULL);
	ps_globals = ts_resource(ps_globals_id);
#endif

	PS(module_number) = module_number;
	REGISTER_INI_ENTRIES();
	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(session)
{
	UNREGISTER_INI_ENTRIES();
	return SUCCESS;
}


PHP_MINFO_FUNCTION(session)
{
	DISPLAY_INI_ENTRIES();
}
