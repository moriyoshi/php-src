#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"

#include "php_rpc.h"
#include "rpc.h"
#include "layer.h"

ZEND_DECLARE_MODULE_GLOBALS(rpc)

static int rpc_global_startup(void);
static int rpc_global_shutdown(void);
static void rpc_globals_ctor(zend_rpc_globals * TSRMLS_DC);
static void rpc_instance_dtor(void *);
static void rpc_class_dtor(void *);
static void rpc_string_dtor(void *);
static void rpc_export_functions(char *, zend_class_entry *, function_entry[] TSRMLS_DC);
static zend_object_value rpc_create_object(zend_class_entry * TSRMLS_DC);

/* object handler */
static void rpc_add_ref(zval * TSRMLS_DC);
static void rpc_del_ref(zval * TSRMLS_DC);
static void rpc_delete(zval * TSRMLS_DC);
static zend_object_value rpc_clone(zval * TSRMLS_DC);
static zval* rpc_read(zval *, zval *, int  TSRMLS_DC);
static void rpc_write(zval *, zval *, zval * TSRMLS_DC);
static zval** rpc_get_property(zval *, zval * TSRMLS_DC);
static zval* rpc_get(zval * TSRMLS_DC);
static void rpc_set(zval **, zval * TSRMLS_DC);
static int rpc_has_property(zval *, zval *, int  TSRMLS_DC);
static void rpc_unset_property(zval *, zval * TSRMLS_DC);
static HashTable* rpc_get_properties(zval * TSRMLS_DC);
static union _zend_function* rpc_get_method(zval *, char *, int TSRMLS_DC);
static int rpc_call(char *, INTERNAL_FUNCTION_PARAMETERS);
static union _zend_function* rpc_get_constructor(zval * TSRMLS_DC);
static int rpc_get_classname(zval *, char **, zend_uint *, int  TSRMLS_DC);
static int rpc_compare(zval *, zval * TSRMLS_DC);
/**/

static zend_object_handlers rpc_handlers = {
	rpc_add_ref,
	rpc_del_ref,
	rpc_delete,
	rpc_clone,
	rpc_read,
	rpc_write,
	rpc_get_property,
	NULL,
	rpc_get,
	rpc_set,
	rpc_has_property,
	rpc_unset_property,
	rpc_get_properties,
	rpc_get_method,
	rpc_call,
	rpc_get_constructor,
	rpc_get_classname,
	rpc_compare
};

/* {{{ rpc_functions[]
 */
function_entry rpc_functions[] = {
	{NULL, NULL, NULL}
};
/* }}} */

/* {{{ rpc_module_entry
 */
zend_module_entry rpc_module_entry = {
	STANDARD_MODULE_HEADER,
	"rpc",
	rpc_functions,
	ZEND_MINIT(rpc),
	ZEND_MSHUTDOWN(rpc),
	NULL,
	NULL,
	ZEND_MINFO(rpc),
	"0.1a",
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

static HashTable *handlers;
static WormHashTable *instance;
static WormHashTable *classes;

static unsigned long thread_count = 0;

#ifdef COMPILE_DL_RPC
ZEND_GET_MODULE(rpc);
#endif

/* {{{ PHP_INI
 */
PHP_INI_BEGIN()
/* TODO: add module specific ini settings here */
PHP_INI_END()
/* }}} */

/* still not sure if MINIT is really only once per server and not once per thread
 * so i keep the init stuff here here
 */
static int rpc_global_startup(void)
{
	handlers = (HashTable *) pemalloc(sizeof(HashTable), TRUE);
	instance = (WormHashTable *) pemalloc(sizeof(WormHashTable), TRUE);
	classes = (WormHashTable *) pemalloc(sizeof(WormHashTable), TRUE);

	zend_hash_init(handlers, 0, NULL, NULL, TRUE);	
	zend_worm_hash_init(instance, 0, NULL, rpc_instance_dtor, TRUE);
	zend_worm_hash_init(classes, 0, NULL, rpc_class_dtor, TRUE);

	FOREACH_HANDLER {
		HANDLER.rpc_handler_init();
		
		/* create a class entry for every rpc handler */
		INIT_OVERLOADED_CLASS_ENTRY((*(HANDLER.ce)),
									HANDLER.name,
									HANDLER.methods,
									NULL,
									NULL,
									NULL);

		HANDLER.ce->create_object = rpc_create_object;

		/* load all available rpc handler into a hash */
		zend_hash_add(handlers, HANDLER.name, strlen(HANDLER.name) + 1, &(HANDLER.handlers), sizeof(rpc_object_handlers *), NULL);
	}

	return SUCCESS;
}

/* same as above for shutdown */
static int rpc_global_shutdown(void)
{
	zend_hash_destroy(handlers);
	zend_worm_hash_destroy(instance);
	zend_worm_hash_destroy(classes);

	pefree(handlers, TRUE);
	pefree(instance, TRUE);
	pefree(classes, TRUE);

	return SUCCESS;
}

static void rpc_globals_ctor(zend_rpc_globals *rpc_globals TSRMLS_DC)
{
}

/* {{{ ZEND_MINIT_FUNCTION
 */
ZEND_MINIT_FUNCTION(rpc)
{
	/* GINIT */
	if (thread_count++ == 0) {
		rpc_global_startup();
	}
	
	FOREACH_HANDLER {
		/* register classes and functions */
		zend_register_internal_class(HANDLER.ce TSRMLS_CC);
		zend_register_functions(HANDLER.functions, NULL, MODULE_PERSISTENT TSRMLS_CC);
	}

	ZEND_INIT_MODULE_GLOBALS(rpc, rpc_globals_ctor, NULL);
	REGISTER_INI_ENTRIES();

	return SUCCESS;
}
/* }}} */

/* {{{ ZEND_MSHUTDOWN_FUNCTION
 */
ZEND_MSHUTDOWN_FUNCTION(rpc)
{
	/* GSHUTDOWN */
	if (--thread_count == 0) {
		rpc_global_shutdown();
	}

	UNREGISTER_INI_ENTRIES();
	return SUCCESS;
}
/* }}} */

/* {{{ ZEND_MINFO_FUNCTION
 */
ZEND_MINFO_FUNCTION(rpc)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "rpc support", "enabled");
	php_info_print_table_end();

	DISPLAY_INI_ENTRIES();
}
/* }}} */

static void rpc_instance_dtor(void *pDest)
{
	rpc_internal **intern;
	
	intern = (rpc_internal **) pDest;

	/* TODO: destruct custom data */

	pefree(*intern, TRUE);
}

static void rpc_class_dtor(void *pDest)
{
	rpc_class_hash **hash;

	hash = (rpc_class_hash **) pDest;

	zend_worm_hash_destroy(&((*hash)->methods));
	zend_worm_hash_destroy(&((*hash)->properties));

	free((*hash)->name.str);
	pefree(*hash, TRUE);
}

static void rpc_string_dtor(void *pDest)
{
	rpc_string **string;

	string = (rpc_string **) pDest;

	free((*string)->str);
	pefree(*string, TRUE);
}

static zend_object_value rpc_create_object(zend_class_entry *class_type TSRMLS_DC)
{
	zend_object_value *zov;
	rpc_internal *intern;
	
	/* set up the object value struct */
	zov = (zend_object_value*) pemalloc(sizeof(zend_object_value), TRUE);
	zov->handlers = &rpc_handlers;

	/* set up the internal representation of our rpc instance */
	intern = (rpc_internal *) pemalloc(sizeof(rpc_internal), TRUE);

	intern->class_name = NULL;
	intern->class_name_len = 0;
	intern->ce = class_type;
	intern->refcount = 1;
	intern->clonecount = 1;
	intern->data = NULL;
	intern->pool_instances = 0;
	intern->mx_handler = tsrm_mutex_alloc();

	if (zend_hash_find(handlers, class_type->name, class_type->name_length + 1, (void **) &(intern->handlers)) == FAILURE) {
		/* TODO: exception */
	}

	/* store the instance in a hash and set the key as handle, thus
	 * we can find it later easily
	 */
	tsrm_mutex_lock(instance->mx_writer);
	{
		zov->handle = zend_hash_next_free_element(&(instance->hash));
		zend_worm_hash_next_index_insert(instance, &intern, sizeof(rpc_internal *), NULL);
	}
	tsrm_mutex_unlock(instance->mx_writer);

	return *zov;
}

/* object handler */

static void rpc_add_ref(zval *object TSRMLS_DC)
{
	GET_INTERNAL(intern);
	RPC_ADDREF(intern);
}

static void rpc_del_ref(zval *object TSRMLS_DC)
{
	rpc_internal **intern;

	if (GET_INTERNAL_EX(intern, object) == SUCCESS) {
		if (RPC_REFCOUNT(intern) > 0) {
			RPC_DELREF(intern);
		}

		if (RPC_REFCOUNT(intern) == 0) {
			zend_worm_hash_index_del(instance, Z_OBJ_HANDLE(*object));
		}
	}
}

static void rpc_delete(zval *object TSRMLS_DC)
{
	rpc_internal **intern;
	
	if (GET_INTERNAL_EX(intern, object) == SUCCESS) {
		if (RPC_CLONECOUNT(intern) > 0) {
			RPC_DELCLONE(intern);
		}

		if (RPC_CLONECOUNT(intern) == 0) {
			zend_worm_hash_index_del(instance, Z_OBJ_HANDLE_P(object));
		}
	}
}

static zend_object_value rpc_clone(zval *object TSRMLS_DC)
{
	GET_INTERNAL(intern);

	/* cloning the underlaying resource is neither possible nor would it
	 * make sense, therfore we return the old zend_object_value and increase
	 * the clone count to not loose the clone when the original object gets
	 * deleted.
	 */
	RPC_ADDCLONE(intern);
	
	/* also increase the refcounter as a clone is just another reference */
	RPC_ADDREF(intern);

	return object->value.obj;
}

static zval* rpc_read(zval *object, zval *member, int type TSRMLS_DC)
{
//	GET_INTERNAL(intern);

	/* FIXME */
	return NULL;
}

static void rpc_write(zval *object, zval *member, zval *value TSRMLS_DC)
{
//	GET_INTERNAL(intern);
	/* FIXME */
}

static zval** rpc_get_property(zval *object, zval *member TSRMLS_DC)
{
/* no idea how to return an object - wait for andi */

//	GET_INTERNAL(intern);

	/* FIXME */
	return NULL;
}

static zval* rpc_get(zval *property TSRMLS_DC)
{
	/* not yet implemented */
	return NULL;
}

static void rpc_set(zval **property, zval *value TSRMLS_DC)
{
	/* not yet implemented */
}

static int rpc_has_property(zval *object, zval *member, int check_empty TSRMLS_DC)
{
//	GET_INTERNAL(intern);
	
	/* FIXME */
	return FAILURE;
}

static void rpc_unset_property(zval *object, zval *member TSRMLS_DC)
{
//	GET_INTERNAL(intern);
	/* FIXME */
}

static HashTable* rpc_get_properties(zval *object TSRMLS_DC)
{
//	GET_INTERNAL(intern);

	/* FIXME */
	return NULL;
}

static union _zend_function* rpc_get_method(zval *object, char *method, int method_len TSRMLS_DC)
{
	zend_function *function;
	GET_INTERNAL(intern);

	if (zend_hash_find(&((*intern)->ce->function_table), method, method_len + 1, &function) == FAILURE) {
		function = (zend_function *) emalloc(sizeof(zend_function));
		function->type = ZEND_OVERLOADED_FUNCTION;
		function->common.arg_types = NULL;
		function->common.function_name = method;
		function->common.scope = NULL;
	}

	return function;
}

static int rpc_call(char *method, INTERNAL_FUNCTION_PARAMETERS)
{
//	zval *object = getThis();
//	GET_INTERNAL(intern);

	return SUCCESS;
}

static union _zend_function* rpc_get_constructor(zval *object TSRMLS_DC)
{
	zend_internal_function *rpc_ctor;
	GET_INTERNAL(intern);
	
	rpc_ctor = (zend_internal_function *) emalloc(sizeof(zend_internal_function));

	rpc_ctor->type = ZEND_INTERNAL_FUNCTION;
	rpc_ctor->function_name = (*intern)->ce->name;
	rpc_ctor->scope = (*intern)->ce;
	rpc_ctor->arg_types = NULL;
	rpc_ctor->handler = ZEND_FN(rpc_load);

	return (zend_function *) rpc_ctor;
}

static int rpc_get_classname(zval *object, char **class_name, zend_uint *class_name_len, int parent TSRMLS_DC)
{
//	GET_INTERNAL(intern);

	/* FIXME */
	return FAILURE;
}

static int rpc_compare(zval *object1, zval *object2 TSRMLS_DC)
{
	/* FIXME */
	return FAILURE;
}

/**/

/* constructor */
ZEND_FUNCTION(rpc_load)
{
	zval *object = getThis();
	zval ***args;
	zend_uint num_args = ZEND_NUM_ARGS(); 
	rpc_class_hash *class_hash;
	rpc_class_hash **class_hash_find = NULL;
	rpc_internal **intern;

	/* check if we were called as a constructor or as a function */
	if (!object) {
		/* we were called as a function so we have to figure out which rpc layer was requested
		 * and then we have to set up a zval containing the object
		 */

		char *key;
		int key_len;

		/* the name of the rpc layer is prepended to '_load' so lets strip everything after
		 * the first '_' away from the function name
		 */
		zend_class_entry **ce;
		key = estrdup(get_active_function_name(TSRMLS_C));
		key_len = strchr(key, '_') - key;
		key[key_len] = '\0';

		/* get the class entry for the requested rpc layer */
		if (zend_hash_find(CG(class_table), key, key_len + 1, (void **) &ce) == FAILURE) {
			/* TODO: exception here */
		}

		/* set up a new zval container */
		ALLOC_ZVAL(object);
		INIT_PZVAL(object);

		Z_TYPE_P(object) = IS_OBJECT;

		/* create a new object */
		object->value.obj = rpc_create_object(*ce TSRMLS_CC);

		/* return the newly created object */
		return_value = object;

		/* now everything is set up the same way as if we were called as a constructor */
	}

	if (GET_INTERNAL_EX(intern, object) == FAILURE) {
		/* TODO: exception */
	}

	/* if classname != integer */
	if ((zend_parse_parameters_ex(ZEND_PARSE_PARAMS_QUIET, 2 TSRMLS_CC, "l", &((*intern)->class_name_len)) == FAILURE) ||
		/* or we have no hash function */
		!((*(*intern)->handlers)->rpc_hash) ||
		/* or integer hashing is not allowed */
		((*(*intern)->handlers)->hash_type != HASH_AS_INT)) {

		/* else check for string - classname */
		if (zend_parse_parameters_ex(ZEND_PARSE_PARAMS_QUIET, 2 TSRMLS_CC, "s", &((*intern)->class_name), &((*intern)->class_name_len)) == FAILURE) {
			/* none of the two possibilities */
			php_error(E_WARNING, "wrong arguments for %s()", get_active_function_name(TSRMLS_C));
		} else {
			/* hash classname if hashing function exists */
			if ((*(*intern)->handlers)->rpc_hash) {

				/* check if already hashed */	
				if (zend_worm_hash_find(classes, (*intern)->class_name, (*intern)->class_name_len + 1, (void **) &class_hash_find) == FAILURE) {
					class_hash = pemalloc(sizeof(rpc_class_hash), TRUE);

					/* set up the cache */
					zend_worm_hash_init(&(class_hash->methods), 0, NULL, rpc_string_dtor, TRUE);
					zend_worm_hash_init(&(class_hash->properties), 0, NULL, rpc_string_dtor, TRUE);

					/* do hashing */
					if ((*(*intern)->handlers)->rpc_hash((*intern)->class_name, (*intern)->class_name_len,
														 &(class_hash->name.str), &(class_hash->name.len), CLASS) == FAILURE) {
						/* TODO: exception */
					}

					/* register with non-hashed key */
					zend_worm_hash_add(classes, (*intern)->class_name, (*intern)->class_name_len + 1, &class_hash, sizeof(rpc_class_hash *), NULL);

					if (class_hash->name.str) {
						/* register string hashcode */
						zend_worm_hash_add(classes, class_hash->name.str, class_hash->name.len + 1, &class_hash, sizeof(rpc_class_hash *), NULL);
					} else if (!class_hash->name.str && ((*(*intern)->handlers)->hash_type == HASH_AS_INT)) {
						/* register int hashcode */
						zend_worm_hash_index_update(classes, class_hash->name.len, &class_hash, sizeof(rpc_class_hash *), NULL);
					}
				} else {
					class_hash = *class_hash_find;
				}
			}
		}
	} else {
		/* integer classname (hashcode) */
		if (zend_worm_hash_index_find(classes, (*intern)->class_name_len, (void**) &class_hash_find) == FAILURE) {
			class_hash = pemalloc(sizeof(rpc_class_hash), TRUE);

			/* set up the cache */
			class_hash->name.str = NULL;
			class_hash->name.len = (*intern)->class_name_len;

			zend_worm_hash_init(&(class_hash->methods), 0, NULL, rpc_string_dtor, TRUE);
			zend_worm_hash_init(&(class_hash->properties), 0, NULL, rpc_string_dtor, TRUE);

			/* register int hashcode, we don't know more */
			zend_worm_hash_index_update(classes, class_hash->name.len, &class_hash, sizeof(rpc_class_hash *), NULL);
		} else {
			class_hash = *class_hash_find;
		}
	}

	/* fetch further parameters */
	args = (zval ***) emalloc(sizeof(zval **) * num_args);

	if (zend_get_parameters_array_ex(num_args, args) == FAILURE) {
		/* TODO: exception */
	}

	/* strip away the first two parameters */
	num_args -= 2;
	args = (num_args > 0) ? &args[2] : NULL;
	
	/* if hash function available */
	if ((*(*intern)->handlers)->rpc_hash) {
		/* assign cache structure */
		(*intern)->hash = class_hash;
		
		/* call the rpc ctor */
		(*(*intern)->handlers)->rpc_ctor(class_hash->name.str, class_hash->name.len, &((*intern)->data), num_args, args);
	} else {
		/* disable caching from now on */
		(*intern)->hash = NULL;

		/* call the rpc ctor */
		(*(*intern)->handlers)->rpc_ctor((*intern)->class_name, (*intern)->class_name_len, &((*intern)->data), num_args, args);
	}

	/* efree hash_find stuff ? */
}

ZEND_FUNCTION(rpc_call)
{
	/* FIXME */
}

ZEND_FUNCTION(rpc_set)
{
	/* FIXME */
}

ZEND_FUNCTION(rpc_get)
{
	/* FIXME */
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
