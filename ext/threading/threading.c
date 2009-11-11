/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2007 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Moriyoshi Koizumi <moriyoshi@php.net>                        |
  +----------------------------------------------------------------------+
*/

/* $Id: header,v 1.16.2.1.2.1 2007/01/01 19:32:09 iliaa Exp $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"

#ifndef ZTS
#error "This extention requires PHP to be built with ZTS support"
#endif

#ifndef GNUPTH
#error "This extention requires PHP to be built with GNU Pth"
#endif

#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_threading.h"
#include "php_main.h"
#include "main/php_network.h"

struct _php_thread_entry_t {
	php_thread_entry_t *parent;
	pth_t t;
	int refcount;
	size_t serial;
	size_t alive_subthread_count;
	struct {
		/* FIXME: this kind of list should be implemented in sparse vector */
		size_t n;
		size_t cap;
		php_thread_entry_t **v;
	} subthreads;
	void ***tsrm_ls;
	void *exit_value;
	unsigned finished:1;
	unsigned destroyed:1;
};

typedef struct _php_thread_global_ctx_t {
	php_thread_entry_t entry;
	pth_t main_thread;
	int le_thread;
	int le_mutex;
	int tsrm_id;
} php_thread_global_ctx_t;

enum php_thread_lock_result {
	PHP_THREAD_LOCK_FAILED = -1,
	PHP_THREAD_LOCK_ACQUIRED = 0,
	PHP_THREAD_LOCK_TIMEOUT = 1
};

typedef struct _php_thread_thread_param_t {
	pth_mutex_t ready_cond_mtx;
	pth_cond_t ready_cond;
	php_thread_entry_t *entry;
	zend_compiler_globals *compiler_globals;
	zend_executor_globals *executor_globals;
	zval *callable;
	int nargs;
	zval ***args;
	int status;
} php_thread_thread_param_t;

typedef struct _php_thread_mutex_t {
	php_thread_entry_t *owner;
	pth_mutex_t m;
	int refcount;
} php_thread_mutex_t;

typedef void *(*php_thread_rsrc_clone_fn_t)(const void *src, int persistent, void ***prev_tsrm_ls TSRMLS_DC);

typedef struct _php_thread_rsrc_desc_t {
	int id;
	unsigned persistent:1;
	size_t size;
	php_thread_rsrc_clone_fn_t clone;
} php_thread_rsrc_desc_t;

static php_thread_global_ctx_t global_ctx;

ZEND_BEGIN_ARG_INFO_EX(arginfo_thread_create, 0, 0, 1)
	ZEND_ARG_INFO(0, callable)
	ZEND_ARG_INFO(0, ...)
ZEND_END_ARG_INFO()

/* {{{ threading_functions[]
 *
 * Every user visible function must have an entry in threading_functions[].
 */
zend_function_entry threading_functions[] = {
	PHP_FE(thread_create,	arginfo_thread_create)
	PHP_FE(thread_suspend,	NULL)
	PHP_FE(thread_resume,	NULL)
	PHP_FE(thread_mutex_create,	NULL)
	PHP_FE(thread_mutex_acquire,	NULL)
	PHP_FE(thread_mutex_release,	NULL)
	{NULL, NULL, NULL}	/* Must be the last line in threading_functions[] */
};
/* }}} */

/* {{{ threading_module_entry
 */
zend_module_entry threading_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"threading",
	threading_functions,
	PHP_MINIT(threading),
	PHP_MSHUTDOWN(threading),
	NULL,
	PHP_RSHUTDOWN(threading),
	PHP_MINFO(threading),
#if ZEND_MODULE_API_NO >= 20010901
	"0.1", /* Replace with version number for your extension */
#endif
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_THREADING
ZEND_GET_MODULE(threading)
#endif

/* {{{ PHP_INI
 */
/* Remove comments and fill if you need to have entries in php.ini
PHP_INI_BEGIN()
	STD_PHP_INI_ENTRY("threading.global_value",	  "42", PHP_INI_ALL, OnUpdateLong, global_value, zend_threading_globals, threading_globals)
	STD_PHP_INI_ENTRY("threading.global_string", "foobar", PHP_INI_ALL, OnUpdateString, global_string, zend_threading_globals, threading_globals)
PHP_INI_END()
*/
/* }}} */

static void php_thread_entry_dispose(php_thread_entry_t **entry TSRMLS_DC);

/* {{{ php_thread_entry_addref() */
static void php_thread_entry_addref(php_thread_entry_t *entry)
{
	++entry->refcount;
}
/* }}} */

/* {{{ php_thread_entry_join() */
static int php_thread_entry_join(php_thread_entry_t *entry,
		void *retval TSRMLS_DC)
{
	if (entry == PHP_THREAD_SELF) {
		return FAILURE;
	}
	php_thread_entry_addref(entry);
	if (!entry->finished) {
		assert(pth_join(entry->t, retval));
		assert(entry->finished);
	}
	php_thread_entry_dispose(&entry TSRMLS_CC);
	return SUCCESS;
}
/* }}} */

/* {{{ php_thread_entry_wait() */
static void php_thread_entry_wait(php_thread_entry_t *entry TSRMLS_DC)
{
	php_thread_entry_t **p, **e = entry->subthreads.v + entry->subthreads.n;
	for (p = entry->subthreads.v; p < e; ++p) {
		if (!*p) {
			continue;
		}
		php_thread_entry_join(*p, NULL TSRMLS_CC);
	}
	assert(entry->alive_subthread_count == 0);
}
/* }}} */

/* {{{ php_thread_entry_suspend() */
static int php_thread_entry_suspend(php_thread_entry_t *entry)
{
	if (entry->destroyed) {
		return FAILURE;
	}
	return pth_suspend(entry->t) ? SUCCESS: FAILURE;
}
/* }}} */

/* {{{ php_thread_entry_resume() */
static int php_thread_entry_resume(php_thread_entry_t *entry)
{
	if (entry->destroyed) {
		return FAILURE;
	}
	return pth_resume(entry->t) ? SUCCESS: FAILURE;
}
/* }}} */

/* {{{ php_thread_entry_clone() */
static php_thread_entry_t *php_thread_entry_clone(
		const php_thread_entry_t *src, int persistent,
		void ***prev_tsrm_ls TSRMLS_DC)
{
	return (php_thread_entry_t *)src;
}
/* }}} */

/* {{{ php_thread_entry_cancel() */
static void php_thread_entry_cancel(php_thread_entry_t *entry TSRMLS_DC)
{
	if (!entry->finished) {
		pth_cancel(entry->t);
		entry->finished = 1;
		--entry->parent->alive_subthread_count;
		php_thread_entry_dispose(&entry TSRMLS_CC);
	}
}
/* }}} */

/* {{{ php_thread_entry_dtor() */
static void php_thread_entry_dtor(php_thread_entry_t *entry TSRMLS_DC)
{
	if (entry->destroyed) {
		return;
	}
	if (!entry->finished) {
		php_thread_entry_cancel(entry TSRMLS_CC);
	}
	if (entry->subthreads.v) {
		php_thread_entry_t **p;
		php_thread_entry_t **e = entry->subthreads.v
				+ entry->subthreads.n;
		for (p = entry->subthreads.v; p < e; ++p) {
			php_thread_entry_dispose(p TSRMLS_CC);
		}
		pefree(entry->subthreads.v, 1);
	}

	entry->destroyed = 1;
}
/* }}} */

/* {{{ php_thread_entry_dispose() */
static void php_thread_entry_dispose(php_thread_entry_t **entry TSRMLS_DC)
{
	if (!*entry) {
		return;
	}

	--(*entry)->refcount;
	if ((*entry)->refcount <= 0) {
		php_thread_entry_t *parent = (*entry)->parent;
		size_t serial = (*entry)->serial;
		php_thread_entry_dtor(*entry TSRMLS_CC);
		pefree(*entry, 1);
		if (parent) {
			parent->subthreads.v[serial] = NULL;
		}
	}
}
/* }}} */

/* {{{ php_thread_entry_ctor() */
static void php_thread_entry_ctor(php_thread_entry_t *entry,
		php_thread_entry_t *parent, size_t serial)
{
	entry->serial = serial;
	entry->alive_subthread_count = 0;
	entry->subthreads.v = NULL;
	entry->subthreads.cap = 0;
	entry->subthreads.n = 0;
	entry->finished = 0;
	entry->destroyed = 0;
	entry->refcount = 1;
	entry->t = NULL;
	entry->parent = parent;
}
/* }}} */

/* {{{ php_thread_mutex_acquire() */
static enum php_thread_lock_result
php_thread_mutex_acquire(php_thread_mutex_t *mtx, double timeout TSRMLS_DC)
{
	int retval;
	pth_event_t ev = NULL;

	if (timeout >= 0) {
		ev = pth_event(
				PTH_EVENT_TIME,
				pth_timeout((long)timeout,
					(long)(timeout - (double)(long)timeout)));
	}
	retval = pth_mutex_acquire(&mtx->m, 0, ev);
	if (ev) {
		pth_event_free(ev, PTH_FREE_THIS);
	}
	if (retval) {
		mtx->owner = PHP_THREAD_SELF;
		return PHP_THREAD_LOCK_ACQUIRED;
	}
	return errno == EINTR ? PHP_THREAD_LOCK_TIMEOUT: PHP_THREAD_LOCK_FAILED;
}
/* }}} */

/* {{{ php_thread_mutex_release() */
static int php_thread_mutex_release(php_thread_mutex_t *mtx TSRMLS_DC)
{
	if (PHP_THREAD_SELF != mtx->owner) {
		return FAILURE;
	}
	return pth_mutex_release(&mtx->m) ? SUCCESS: FAILURE;
}
/* }}} */

/* {{{ php_thread_mutex_addref() */
static void php_thread_mutex_addref(php_thread_mutex_t *mtx)
{
	++mtx->refcount;
}
/* }}} */

/* {{{ php_thread_mutex_clone() */
static php_thread_mutex_t *php_thread_mutex_clone(
		const php_thread_mutex_t *src, int persistent,
		void ***prev_tsrm_ls TSRMLS_DC)
{
	php_thread_mutex_addref((php_thread_mutex_t *)src);
	return (php_thread_mutex_t *)src;
}
/* }}} */

/* {{{ php_thread_mutex_dtor() */
static void php_thread_mutex_dtor(php_thread_mutex_t *mtx TSRMLS_DC)
{
	if (PHP_THREAD_SELF == mtx->owner) {
		pth_mutex_release(&mtx->m);
		mtx->owner = NULL;
	}
}
/* }}} */

/* {{{ php_thread_mutex_dispose() */
static void php_thread_mutex_dispose(php_thread_mutex_t **mtx TSRMLS_DC)
{
	if (!*mtx) {
		return;
	}
	--(*mtx)->refcount;
	if ((*mtx)->refcount <= 0) {
		php_thread_mutex_dtor(*mtx TSRMLS_CC);
		pefree(*mtx, 1);
	}
}
/* }}} */

/* {{{ php_thread_mutex_ctor() */
static int php_thread_mutex_ctor(php_thread_mutex_t *mtx)
{
	if (!pth_mutex_init(&mtx->m)) {
		return FAILURE;
	}
	mtx->refcount = 1;
	mtx->owner = NULL;
	return SUCCESS;
}
/* }}} */

/* {{{ php_thread_executor_globals_reinit() */
static void php_thread_executor_globals_reinit(zend_executor_globals *dest,
		zend_executor_globals *src)
{
	dest->current_module = src->current_module;
}
/* }}} */

/* {{{ php_thread_compiler_globals_reinit() */
static void php_thread_compiler_globals_reinit(zend_compiler_globals *dest,
		zend_compiler_globals *src)
{
	zend_hash_clean(dest->function_table);
	zend_hash_copy(dest->function_table, src->function_table,
			(copy_ctor_func_t)function_add_ref, NULL,
			sizeof(zend_function));
	zend_hash_clean(dest->class_table);
	zend_hash_copy(dest->class_table, src->class_table,
			(copy_ctor_func_t)zend_class_add_ref, NULL,
			sizeof(zend_class_entry*));
}
/* }}} */

/* {{{ php_thread_get_stream_persistent_id() */
static const char *php_thread_get_stream_persistent_id(const php_stream *strm TSRMLS_DC)
{
	HashPosition pos;
	HashTable *persistent_list = &EG(persistent_list);
	zend_hash_key key;
	int key_type;
	for (zend_hash_internal_pointer_reset_ex(persistent_list, &pos);
			HASH_KEY_NON_EXISTANT != (key_type = zend_hash_get_current_key_ex(
				persistent_list, &key.arKey,
				&key.nKeyLength, &key.h, 0, &pos));
			zend_hash_move_forward_ex(persistent_list, &pos)) {
		zend_rsrc_list_entry *i;
		zend_hash_get_current_data_ex(persistent_list, (void**)&i, &pos);
		if (i->ptr == strm) {
			return key.arKey;
		}
	}
	return NULL;
}
/* }}} */

/* {{{ php_thread_stream_data_copy_ctor() */
static int php_thread_netstream_data_copy_ctor(php_netstream_data_t *self,
		const php_netstream_data_t *src, int persistent,
		void ***prev_tsrm_ls TSRMLS_DC)
{
	*self = *src;
	self->socket = dup(self->socket);
	if (self->socket == -1)
		return FAILURE;
	return SUCCESS;
}
/* }}} */

/* {{{ php_thread_stream_basic_clone() */
static php_stream *php_thread_stream_basic_clone(
		const php_stream *src, int persistent, void ***prev_tsrm_ls TSRMLS_DC)
{
	php_stream *retval;

	retval = pemalloc(sizeof(*retval), persistent);
	if (!retval) {
		return NULL;
	}

	if (src->readbuf) {
		retval->readbuf = pemalloc(src->readbuflen, persistent);
		if (!retval->readbuf) {
			pefree(retval, persistent);
			return NULL;
		}
		memcpy(retval->readbuf, src->readbuf, src->readbuflen);
	} else {
		retval->readbuf = NULL;
	}

	if (src->orig_path) {
		retval->orig_path = pestrdup(src->orig_path, persistent);
		if (!retval->orig_path) {
			pefree(retval->readbuf, persistent);
			pefree(retval, persistent);
			return NULL;
		}
	} else {
		retval->orig_path = NULL;
	}

	retval->readbuflen = src->readbuflen;
	retval->ops = src->ops;
	retval->flags = src->flags;
	retval->chunk_size = src->chunk_size;
	retval->is_persistent = persistent;
	retval->abstract = NULL;
	retval->wrapperthis = NULL;
	retval->wrapperdata = NULL;
	retval->context = NULL;
	retval->rsrc_id = 0;
	retval->in_free = 0;
	retval->stdiocast = NULL;
	retval->readfilters.stream = retval;
	retval->writefilters.stream = retval;

	memcpy(retval->mode, src->mode, sizeof(retval->mode));

	return retval;
}
/* }}} */

/* {{{ php_thread_stream_clone() */
static php_stream *php_thread_stream_clone(
		const php_stream *src, int persistent, void ***prev_tsrm_ls TSRMLS_DC)
{
	php_stream *retval = NULL;

	if (src->ops == &php_stream_socket_ops) {
		retval = php_thread_stream_basic_clone(src, persistent, prev_tsrm_ls
				TSRMLS_CC);
		if (!retval) {
			return NULL;
		}
		php_netstream_data_t *data = pemalloc(sizeof(*data), persistent);
		if (!data) {
			php_stream_free(retval, 0);
			return NULL;
		}
		if (FAILURE == php_thread_netstream_data_copy_ctor(data,
				(php_netstream_data_t*)src->abstract, persistent,
				prev_tsrm_ls TSRMLS_CC)) {
			pefree(data, persistent);
			php_stream_free(retval, 0);
			return NULL;
		}
		retval->abstract = data;
	} else if (src->ops == &php_stream_stdio_ops) {
		int fd;
		const char *persistent_id = NULL;
		if (_php_stream_cast((php_stream *)src,
					PHP_STREAM_AS_FD, (void **)&fd, 0, prev_tsrm_ls) == FAILURE) {
			return NULL;
		}
		fd = dup(fd);
		if (fd == -1) {
			return NULL;
		}
		if (persistent) {
			persistent_id = php_thread_get_stream_persistent_id(src, prev_tsrm_ls);
			if (!persistent_id) {
				return NULL;
			}
		}
		retval = php_stream_fopen_from_fd(fd, src->mode, persistent_id);
	}
	return retval;
}
/* }}} */

/* {{{ php_thread_get_rsrc_desc() */
static int php_thread_get_rsrc_desc(php_thread_rsrc_desc_t *retval, int le_id)
{
	retval->id = le_id;
	retval->persistent = 0;

	if (le_id == php_file_le_stream()) {
		retval->size = sizeof(php_stream);
		retval->clone = (php_thread_rsrc_clone_fn_t)php_thread_stream_clone;
	} else if (le_id == php_file_le_pstream()) {
		retval->size = sizeof(php_stream);
		retval->persistent = 1;
		retval->clone = (php_thread_rsrc_clone_fn_t)php_thread_stream_clone;
	} else if (le_id == global_ctx.le_thread) {
		retval->size = sizeof(php_thread_entry_t);
		retval->persistent = 0;
		retval->clone = (php_thread_rsrc_clone_fn_t)php_thread_entry_clone;
	} else if (le_id == global_ctx.le_mutex) {
		retval->size = sizeof(php_thread_mutex_t);
		retval->persistent = 0;
		retval->clone = (php_thread_rsrc_clone_fn_t)php_thread_mutex_clone;
	} else {
		return FAILURE;
	}
	return SUCCESS;
}
/* }}} */

/* {{{ php_thread_clone_resource() */
static void *php_thread_clone_resource(const php_thread_rsrc_desc_t *desc,
		void *ptr, void ***prev_tsrm_ls TSRMLS_DC)
{
	assert(desc->clone);
	return desc->clone(ptr, desc->persistent, prev_tsrm_ls TSRMLS_CC);
}
/* }}} */

static int php_thread_convert_object_ref(zval **retval, zval *src,
		void ***prev_tsrm_ls TSRMLS_DC);

/* {{{ php_thread_convert_object_refs_in_hash() */
static HashTable *php_thread_convert_object_refs_in_hash(HashTable *src,
		void ***prev_tsrm_ls TSRMLS_DC)
{
	HashTable *retval;
	HashPosition pos;
	zend_hash_key key;
	int key_type;

	ALLOC_HASHTABLE(retval);
	zend_hash_init(retval, 0, NULL, ZVAL_PTR_DTOR, 0);

	for (zend_hash_internal_pointer_reset_ex(src, &pos);
			HASH_KEY_NON_EXISTANT != (
				key_type = zend_hash_get_current_key_ex(src, &key.arKey,
					&key.nKeyLength, &key.h, 0, &pos));
			zend_hash_move_forward_ex(src, &pos)) {
		zval **orig;
		zval *val;
		zend_hash_get_current_data_ex(src, (void **)&orig, &pos);
		if (FAILURE == php_thread_convert_object_ref(&val, *orig,
					prev_tsrm_ls TSRMLS_CC)) {
			zend_hash_destroy(retval);
			FREE_HASHTABLE(retval);
			return NULL;
		}
		zend_hash_quick_add(retval, key.arKey,
				key_type == HASH_KEY_IS_LONG ? 0: key.nKeyLength, key.h, &val,
				sizeof(zval*), NULL);
	}
	return retval;
}
/* }}} */

/* {{{ php_thread_convert_object_ref() */
static int php_thread_convert_object_ref(zval **retval, zval *src,
		void ***prev_tsrm_ls TSRMLS_DC)
{
	ALLOC_ZVAL(*retval);
	if (Z_ISREF_P(src)) {
		(*retval)->type = IS_NULL;
	} else {
		if (Z_TYPE_P(src) == IS_OBJECT) {
			zend_class_entry *ce;
			HashTable *props;
			if (!Z_OBJ_HT_P(src)->get_class_entry
					|| !Z_OBJ_HT_P(src)->get_properties) {
				goto fail;
			}
			ce = Z_OBJ_HT_P(src)->get_class_entry(src, prev_tsrm_ls);
			ce = zend_fetch_class(ce->name, ce->name_length, 0 TSRMLS_CC);
			if (ce == NULL) {
				goto fail;
			}
			props = Z_OBJ_HT_P(src)->get_properties(src, prev_tsrm_ls);
			if (!props) {
				goto fail;
			}
			props = php_thread_convert_object_refs_in_hash(props,
					prev_tsrm_ls TSRMLS_CC);
			(*retval)->type = IS_OBJECT;
			if (FAILURE == object_and_properties_init(*retval, ce, props)) {
				goto fail;
			}
		} else if (src->type == IS_ARRAY) {
			(*retval)->type = IS_ARRAY;
			(*retval)->value.ht = php_thread_convert_object_refs_in_hash(
					src->value.ht, prev_tsrm_ls TSRMLS_CC);
			if (!(*retval)->value.ht) {
				goto fail;
			}
		} else if (src->type == IS_RESOURCE) {
			int id;
			zend_rsrc_list_entry le;
			php_thread_rsrc_desc_t desc;
			void *rsrc_ptr;
			rsrc_ptr = _zend_list_find(src->value.lval, &le.type, prev_tsrm_ls);
			if (!rsrc_ptr) {
				goto fail;
			}
			if (FAILURE == php_thread_get_rsrc_desc(&desc, le.type)) {
				goto fail;
			}
			le.ptr = php_thread_clone_resource(&desc, rsrc_ptr, prev_tsrm_ls
					TSRMLS_CC);
			if (!le.ptr) {
				goto fail;
			}
			php_stream_auto_cleanup((php_stream*)le.ptr);
			id = zend_hash_next_free_element(&EG(regular_list));
			zend_hash_index_update(&EG(regular_list), id, &le,
					sizeof(le), NULL);
			(*retval)->type = IS_RESOURCE;
			(*retval)->value.lval = id;
		} else {
			**retval = *src;
			zval_copy_ctor(*retval);
		}
	}
	Z_SET_REFCOUNT_P(*retval, 1);
	Z_UNSET_ISREF_P(*retval);
	return SUCCESS;
fail:
	FREE_ZVAL(*retval);
	return FAILURE;
}
/* }}} */

/* {{{ _php_thread_entry_func() */
static void *_php_thread_entry_func(php_thread_thread_param_t *param)
{
	TSRMLS_FETCH();
	php_thread_entry_t *entry = param->entry;
	int nargs = param->nargs;
	zval **args;
	zval *callable;
	int i;

	if (FAILURE == php_request_startup(TSRMLS_C)) {
		assert(pth_mutex_acquire(&param->ready_cond_mtx, 0, NULL));
		assert(pth_cond_notify(&param->ready_cond, 0));
		assert(pth_mutex_release(&param->ready_cond_mtx));
		return NULL;
	}

	entry->tsrm_ls = tsrm_ls;

	++entry->parent->alive_subthread_count;
	php_thread_entry_addref(entry);

	zend_try {
		PHP_THREAD_SELF = entry;

		php_thread_compiler_globals_reinit(
				(zend_compiler_globals*)(*tsrm_ls)[TSRM_UNSHUFFLE_RSRC_ID(compiler_globals_id)],
				(zend_compiler_globals*)(*entry->parent->tsrm_ls)[TSRM_UNSHUFFLE_RSRC_ID(compiler_globals_id)]);
		php_thread_executor_globals_reinit(
				(zend_executor_globals*)(*tsrm_ls)[TSRM_UNSHUFFLE_RSRC_ID(executor_globals_id)],
				(zend_executor_globals*)(*entry->parent->tsrm_ls)[TSRM_UNSHUFFLE_RSRC_ID(executor_globals_id)]);

		args = safe_emalloc(nargs, sizeof(zval*), 0);
		for (i = 0; i < nargs; ++i) {
			if (FAILURE == php_thread_convert_object_ref(&args[i],
					*param->args[i], entry->parent->tsrm_ls TSRMLS_CC)) {
				zend_bailout();
			}
		}

		if (FAILURE == php_thread_convert_object_ref(&callable, param->callable,
				entry->parent->tsrm_ls TSRMLS_CC)) {
			zend_bailout();
		}

		param->status = 0; /* no error */
	} zend_end_try();

	assert(pth_mutex_acquire(&param->ready_cond_mtx, 0, NULL));
	assert(pth_cond_notify(&param->ready_cond, 0));
	assert(pth_mutex_release(&param->ready_cond_mtx));

	if (param->status) {
		goto out;
	}

	zend_try {
		zval retval;
		retval.type = IS_NULL;
		call_user_function(CG(function_table), NULL, callable,
				&retval, nargs, args TSRMLS_CC);
		zval_dtor(&retval);
	} zend_end_try();

	php_thread_entry_wait(entry TSRMLS_CC);

out:
	for (i = 0; i < nargs; ++i) {
		zval_ptr_dtor(&args[i]);
	}

	zval_ptr_dtor(&callable);
	efree(args);

	php_request_shutdown(NULL);

	entry->finished = 1;
	--entry->parent->alive_subthread_count;

	php_thread_entry_dispose(&entry TSRMLS_CC);

	return (void*)(intptr_t)EG(exit_status);
}
/* }}} */

/* {{{ proto resource thread_create(callable entry_function, ...)
   Creates a new thread and returns the thread handle */
PHP_FUNCTION(thread_create)
{
	zval ***args = NULL;
	char *callable_str_repr = NULL;
	int nargs;

	{
		nargs = ZEND_NUM_ARGS();
		if (nargs < 1) {
			ZEND_WRONG_PARAM_COUNT();
			return;
		}
		args = (zval ***)safe_emalloc(nargs, sizeof(zval *), 0);
		if (FAILURE == zend_get_parameters_array_ex(nargs, args)) {
			ZEND_WRONG_PARAM_COUNT();
			RETVAL_FALSE;
			goto out;
		}
	}

	if (!zend_is_callable(*args[0],
				IS_CALLABLE_CHECK_NO_ACCESS,
				&callable_str_repr TSRMLS_CC)) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "The argument (%s) is not callable", callable_str_repr);
		efree(callable_str_repr);
		RETVAL_FALSE;
		goto out;
	}
	efree(callable_str_repr);

	{
		php_thread_entry_t *current_entry = PHP_THREAD_SELF;
		php_thread_thread_param_t param = {
			PTH_MUTEX_INIT,
			PTH_COND_INIT,
			NULL,
			(zend_compiler_globals*)(*tsrm_ls)[TSRM_UNSHUFFLE_RSRC_ID(compiler_globals_id)],
			(zend_executor_globals*)(*tsrm_ls)[TSRM_UNSHUFFLE_RSRC_ID(executor_globals_id)],
			*args[0],
			nargs - 1,
			args + 1,
			-1
		};

		param.entry = pemalloc(sizeof(*param.entry), 1);
		if (!param.entry) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Insufficient memory");
			RETVAL_FALSE;
			goto out;
		}

		if (current_entry->subthreads.cap <= current_entry->subthreads.n) {
			size_t new_cap = current_entry->subthreads.cap == 0 ?
					1: current_entry->subthreads.cap * 2;
			php_thread_entry_t **new_list = NULL;
			if (new_cap / 2 != current_entry->subthreads.cap) {
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "Insufficient memory");
				RETVAL_FALSE;
				goto out;
			}
			new_list = safe_perealloc(current_entry->subthreads.v,
					new_cap, sizeof(*new_list), 0, 1);
			if (!new_list) {
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "Insufficient memory");
				RETVAL_FALSE;
				goto out;
			}
			current_entry->subthreads.cap = new_cap;
			current_entry->subthreads.v = new_list;
		}

		php_thread_entry_ctor(param.entry, current_entry,
				current_entry->subthreads.n);
		++current_entry->subthreads.n;
		param.entry->t = pth_spawn(PTH_ATTR_DEFAULT,
				(void*(*)(void*))_php_thread_entry_func, &param);
		if (!param.entry->t) {
			--current_entry->subthreads.n;
			pefree(param.entry, 1);
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed to spawn a new thread");
			RETVAL_FALSE;
			goto out;
		}

		assert(pth_mutex_acquire(&param.ready_cond_mtx, 0, NULL));
		assert(pth_cond_await(&param.ready_cond, &param.ready_cond_mtx, NULL));
		assert(pth_mutex_release(&param.ready_cond_mtx));

		if (param.status) {
			--current_entry->subthreads.n;
			pefree(param.entry, 1);
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed to spawn a new thread");
			RETVAL_FALSE;
			goto out;
		}

		current_entry->subthreads.v[param.entry->serial] = param.entry;

		ZEND_REGISTER_RESOURCE(return_value, param.entry, global_ctx.le_thread);
	}
out:
	if (args) {
		efree(args);
	}
}
/* }}} */

/* {{{ proto void thread_suspend(resource thread)
   Suspends the specified thread */
PHP_FUNCTION(thread_suspend)
{
	zval *zv;
	php_thread_entry_t *entry;

	if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &zv)) {
		RETURN_FALSE;
	}

	ZEND_FETCH_RESOURCE(entry, php_thread_entry_t *, &zv, -1, "thread handle",
			global_ctx.le_thread);

	php_thread_entry_suspend(entry);
}
/* }}} */

/* {{{ proto void thread_resume(resource thread)
   Resumes a suspended thread */
PHP_FUNCTION(thread_resume)
{
	zval *zv;
	php_thread_entry_t *entry;

	if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &zv)) {
		RETURN_FALSE;
	}

	ZEND_FETCH_RESOURCE(entry, php_thread_entry_t *, &zv, -1, "thread handle",
			global_ctx.le_thread);

	php_thread_entry_resume(entry);
}
/* }}} */

/* {{{ proto resource thread_mutex_create()
   Creates a mutex */
PHP_FUNCTION(thread_mutex_create)
{
	php_thread_mutex_t *mtx = pemalloc(sizeof(*mtx), 1);
	if (FAILURE == php_thread_mutex_ctor(mtx)) {
		pefree(mtx, 1);
		RETURN_FALSE;
	}
	ZEND_REGISTER_RESOURCE(return_value, mtx, global_ctx.le_mutex);
}
/* }}} */

/* {{{ proto mixed thread_mutex_acquire(resource mutex [, float timeout])
   Acquires a mutex lock ownership */
PHP_FUNCTION(thread_mutex_acquire)
{
	zval *zv;
	double timeout = -1.0;
	php_thread_mutex_t *mtx;

	if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r|d", &zv, &timeout)) {
		RETURN_FALSE;
	}

	ZEND_FETCH_RESOURCE(mtx, php_thread_mutex_t *, &zv, -1, "thread mutex",
			global_ctx.le_mutex);

	switch (php_thread_mutex_acquire(mtx, timeout TSRMLS_CC)) {
	case PHP_THREAD_LOCK_FAILED:
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed to acquire a mutex ownership");
		RETURN_FALSE;
	case PHP_THREAD_LOCK_ACQUIRED:
		RETURN_TRUE;
	case PHP_THREAD_LOCK_TIMEOUT:
		RETURN_LONG(0);
	}
}
/* }}} */

/* {{{ proto bool thread_mutex_release(resource mutex)
   Releases a mutex lock ownership */
PHP_FUNCTION(thread_mutex_release)
{
	zval *zv;
	php_thread_mutex_t *mtx;

	if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &zv)) {
		RETURN_FALSE;
	}

	ZEND_FETCH_RESOURCE(mtx, php_thread_mutex_t *, &zv, -1, "thread mutex",
			global_ctx.le_mutex);

	if (FAILURE == php_thread_mutex_release(mtx TSRMLS_CC)) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed to release a mutex; possibly it is not owned by the current thread");
	}
	RETURN_TRUE;
}
/* }}} */

static void _php_thread_free_thread_entry(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	php_thread_entry_dispose((php_thread_entry_t **)&rsrc->ptr TSRMLS_CC);
}

static void _php_thread_free_mutex_entry(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	php_thread_mutex_dispose((php_thread_mutex_t **)&rsrc->ptr TSRMLS_CC);
}

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(threading)
{
	php_thread_entry_ctor(&global_ctx.entry, NULL, 0);
	global_ctx.entry.t = pth_self();
	global_ctx.entry.tsrm_ls = tsrm_ls;
	ts_allocate_id(&global_ctx.tsrm_id,
			sizeof(php_thread_entry_t*), NULL, NULL);
	global_ctx.le_thread = zend_register_list_destructors_ex(
			(rsrc_dtor_func_t)_php_thread_free_thread_entry,
			NULL, "thread handle", module_number);
	global_ctx.le_mutex = zend_register_list_destructors_ex(
			(rsrc_dtor_func_t)_php_thread_free_mutex_entry,
			NULL, "thread mutex", module_number);
	PHP_THREAD_SELF = &global_ctx.entry;
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(threading)
{
	php_thread_entry_dtor(&global_ctx.entry TSRMLS_CC);
	/* uncomment this line if you have INI entries
	UNREGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(threading)
{
	php_thread_entry_t *entry = PHP_THREAD_SELF;
	if (entry != &global_ctx.entry) {
		return SUCCESS;
	}
	php_thread_entry_wait(entry TSRMLS_CC);
	entry->finished = 1;
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(threading)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "threading support", "enabled");
	php_info_print_table_end();

	/* Remove comments if you have entries in php.ini
	DISPLAY_INI_ENTRIES();
	*/
}
/* }}} */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
