/*
   +----------------------------------------------------------------------+
   | Zend Engine                                                          |
   +----------------------------------------------------------------------+
   | Copyright (c) 1998-2014 Zend Technologies Ltd. (http://www.zend.com) |
   +----------------------------------------------------------------------+
   | This source file is subject to version 2.00 of the Zend license,     |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.zend.com/license/2_00.txt.                                |
   | If you did not receive a copy of the Zend license and are unable to  |
   | obtain it through the world-wide-web, please send a note to          |
   | license@zend.com so we can mail you a copy immediately.              |
   +----------------------------------------------------------------------+
   | Authors: Bob Weinand <bwoebi@php.net>                                |
   |          Dmitry Stogov <dmitry@zend.com>                             |
   +----------------------------------------------------------------------+
*/

/* $Id$ */

#include "zend_ast.h"
#include "zend_API.h"
#include "zend_operators.h"
#include "zend_interfaces.h"
#include "zend_object_handlers.h"

ZEND_API zend_ast *zend_ast_create_constant(zval *zv)
{
	zend_ast *ast = emalloc(sizeof(zend_ast) + sizeof(zval));
	ast->kind = ZEND_CONST;
	ast->children = 0;
	ast->u.val = (zval*)(ast + 1);
	INIT_PZVAL_COPY(ast->u.val, zv);
	return ast;
}

ZEND_API zend_ast* zend_ast_create_unary(uint kind, zend_ast *op0)
{
	zend_ast *ast = emalloc(sizeof(zend_ast));
	ast->kind = kind;
	ast->children = 1;
	(&ast->u.child)[0] = op0;
	return ast;
}

ZEND_API zend_ast* zend_ast_create_binary(uint kind, zend_ast *op0, zend_ast *op1)
{
	zend_ast *ast = emalloc(sizeof(zend_ast) + sizeof(zend_ast*));
	ast->kind = kind;
	ast->children = 2;
	(&ast->u.child)[0] = op0;
	(&ast->u.child)[1] = op1;
	return ast;
}

ZEND_API zend_ast* zend_ast_create_ternary(uint kind, zend_ast *op0, zend_ast *op1, zend_ast *op2)
{
	zend_ast *ast = emalloc(sizeof(zend_ast) + sizeof(zend_ast*) * 2);
	ast->kind = kind;
	ast->children = 3;
	(&ast->u.child)[0] = op0;
	(&ast->u.child)[1] = op1;
	(&ast->u.child)[2] = op2;
	return ast;
}

ZEND_API int zend_ast_is_ct_constant(zend_ast *ast)
{
	int i;

	if (ast->kind == ZEND_CONST) {
		return !IS_CONSTANT_TYPE(Z_TYPE_P(ast->u.val));
	} else {
		for (i = 0; i < ast->children; i++) {
			if ((&ast->u.child)[i]) {
				if (!zend_ast_is_ct_constant((&ast->u.child)[i])) {
					return 0;
				}
			}
		}
		return 1;
	}
}

ZEND_API void zend_ast_evaluate(zval *result, zend_ast *ast, zend_class_entry *scope TSRMLS_DC)
{
	zval op1, op2;

	switch (ast->kind) {
		case ZEND_ADD:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			zend_ast_evaluate(&op2, (&ast->u.child)[1], scope TSRMLS_CC);
			add_function(result, &op1, &op2 TSRMLS_CC);
			zval_dtor(&op1);
			zval_dtor(&op2);
			break;
		case ZEND_SUB:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			zend_ast_evaluate(&op2, (&ast->u.child)[1], scope TSRMLS_CC);
			sub_function(result, &op1, &op2 TSRMLS_CC);
			zval_dtor(&op1);
			zval_dtor(&op2);
			break;
		case ZEND_MUL:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			zend_ast_evaluate(&op2, (&ast->u.child)[1], scope TSRMLS_CC);
			mul_function(result, &op1, &op2 TSRMLS_CC);
			zval_dtor(&op1);
			zval_dtor(&op2);
			break;
		case ZEND_POW:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			zend_ast_evaluate(&op2, (&ast->u.child)[1], scope TSRMLS_CC);
			pow_function(result, &op1, &op2 TSRMLS_CC);
			zval_dtor(&op1);
			zval_dtor(&op2);
			break;
		case ZEND_DIV:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			zend_ast_evaluate(&op2, (&ast->u.child)[1], scope TSRMLS_CC);
			div_function(result, &op1, &op2 TSRMLS_CC);
			zval_dtor(&op1);
			zval_dtor(&op2);
			break;
		case ZEND_MOD:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			zend_ast_evaluate(&op2, (&ast->u.child)[1], scope TSRMLS_CC);
			mod_function(result, &op1, &op2 TSRMLS_CC);
			zval_dtor(&op1);
			zval_dtor(&op2);
			break;
		case ZEND_SL:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			zend_ast_evaluate(&op2, (&ast->u.child)[1], scope TSRMLS_CC);
			shift_left_function(result, &op1, &op2 TSRMLS_CC);
			zval_dtor(&op1);
			zval_dtor(&op2);
			break;
		case ZEND_SR:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			zend_ast_evaluate(&op2, (&ast->u.child)[1], scope TSRMLS_CC);
			shift_right_function(result, &op1, &op2 TSRMLS_CC);
			zval_dtor(&op1);
			zval_dtor(&op2);
			break;
		case ZEND_CONCAT:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			zend_ast_evaluate(&op2, (&ast->u.child)[1], scope TSRMLS_CC);
			concat_function(result, &op1, &op2 TSRMLS_CC);
			zval_dtor(&op1);
			zval_dtor(&op2);
			break;
		case ZEND_BW_OR:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			zend_ast_evaluate(&op2, (&ast->u.child)[1], scope TSRMLS_CC);
			bitwise_or_function(result, &op1, &op2 TSRMLS_CC);
			zval_dtor(&op1);
			zval_dtor(&op2);
			break;
		case ZEND_BW_AND:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			zend_ast_evaluate(&op2, (&ast->u.child)[1], scope TSRMLS_CC);
			bitwise_and_function(result, &op1, &op2 TSRMLS_CC);
			zval_dtor(&op1);
			zval_dtor(&op2);
			break;
		case ZEND_BW_XOR:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			zend_ast_evaluate(&op2, (&ast->u.child)[1], scope TSRMLS_CC);
			bitwise_xor_function(result, &op1, &op2 TSRMLS_CC);
			zval_dtor(&op1);
			zval_dtor(&op2);
			break;
		case ZEND_BW_NOT:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			bitwise_not_function(result, &op1 TSRMLS_CC);
			zval_dtor(&op1);
			break;
		case ZEND_BOOL_NOT:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			boolean_not_function(result, &op1 TSRMLS_CC);
			zval_dtor(&op1);
			break;
		case ZEND_BOOL_XOR:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			zend_ast_evaluate(&op2, (&ast->u.child)[1], scope TSRMLS_CC);
			boolean_xor_function(result, &op1, &op2 TSRMLS_CC);
			zval_dtor(&op1);
			zval_dtor(&op2);
			break;
		case ZEND_IS_IDENTICAL:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			zend_ast_evaluate(&op2, (&ast->u.child)[1], scope TSRMLS_CC);
			is_identical_function(result, &op1, &op2 TSRMLS_CC);
			zval_dtor(&op1);
			zval_dtor(&op2);
			break;
		case ZEND_IS_NOT_IDENTICAL:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			zend_ast_evaluate(&op2, (&ast->u.child)[1], scope TSRMLS_CC);
			is_not_identical_function(result, &op1, &op2 TSRMLS_CC);
			zval_dtor(&op1);
			zval_dtor(&op2);
			break;
		case ZEND_IS_EQUAL:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			zend_ast_evaluate(&op2, (&ast->u.child)[1], scope TSRMLS_CC);
			is_equal_function(result, &op1, &op2 TSRMLS_CC);
			zval_dtor(&op1);
			zval_dtor(&op2);
			break;
		case ZEND_IS_NOT_EQUAL:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			zend_ast_evaluate(&op2, (&ast->u.child)[1], scope TSRMLS_CC);
			is_not_equal_function(result, &op1, &op2 TSRMLS_CC);
			zval_dtor(&op1);
			zval_dtor(&op2);
			break;
		case ZEND_IS_SMALLER:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			zend_ast_evaluate(&op2, (&ast->u.child)[1], scope TSRMLS_CC);
			is_smaller_function(result, &op1, &op2 TSRMLS_CC);
			zval_dtor(&op1);
			zval_dtor(&op2);
			break;
		case ZEND_IS_SMALLER_OR_EQUAL:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			zend_ast_evaluate(&op2, (&ast->u.child)[1], scope TSRMLS_CC);
			is_smaller_or_equal_function(result, &op1, &op2 TSRMLS_CC);
			zval_dtor(&op1);
			zval_dtor(&op2);
			break;
		case ZEND_CONST:
			*result = *ast->u.val;
			zval_copy_ctor(result);
			if (IS_CONSTANT_TYPE(Z_TYPE_P(result))) {
				zval_update_constant_ex(&result, (void *) 1, scope TSRMLS_CC);
			}
			break;
		case ZEND_BOOL_AND:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			if (zend_is_true(&op1 TSRMLS_CC)) {
				zend_ast_evaluate(&op2, (&ast->u.child)[1], scope TSRMLS_CC);
				ZVAL_BOOL(result, zend_is_true(&op2 TSRMLS_CC));
				zval_dtor(&op2);
			} else {
				ZVAL_BOOL(result, 0);
			}
			zval_dtor(&op1);
			break;
		case ZEND_BOOL_OR:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			if (zend_is_true(&op1 TSRMLS_CC)) {
				ZVAL_BOOL(result, 1);
			} else {
				zend_ast_evaluate(&op2, (&ast->u.child)[1], scope TSRMLS_CC);
				ZVAL_BOOL(result, zend_is_true(&op2 TSRMLS_CC));
				zval_dtor(&op2);
			}
			zval_dtor(&op1);
			break;
		case ZEND_SELECT:
			zend_ast_evaluate(&op1, (&ast->u.child)[0], scope TSRMLS_CC);
			if (zend_is_true(&op1 TSRMLS_CC)) {
				if (!(&ast->u.child)[1]) {
					*result = op1;
				} else {
					zend_ast_evaluate(result, (&ast->u.child)[1], scope TSRMLS_CC);
					zval_dtor(&op1);
				}
			} else {
				zend_ast_evaluate(result, (&ast->u.child)[2], scope TSRMLS_CC);
				zval_dtor(&op1);
			}
			break;
		case ZEND_UNARY_PLUS:
			ZVAL_LONG(&op1, 0);
			zend_ast_evaluate(&op2, (&ast->u.child)[0], scope TSRMLS_CC);
			add_function(result, &op1, &op2 TSRMLS_CC);
			zval_dtor(&op2);
			break;
		case ZEND_UNARY_MINUS:
			ZVAL_LONG(&op1, 0);
			zend_ast_evaluate(&op2, (&ast->u.child)[0], scope TSRMLS_CC);
			sub_function(result, &op1, &op2 TSRMLS_CC);
			zval_dtor(&op2);
			break;
		default:
			zend_error(E_ERROR, "Unsupported constant expression");
	}
}

ZEND_API zend_ast *zend_ast_copy(zend_ast *ast)
{
	if (ast == NULL) {
		return NULL;
	} else if (ast->kind == ZEND_CONST) {
		zend_ast *copy = zend_ast_create_constant(ast->u.val);
		zval_copy_ctor(copy->u.val);
		return copy;
	} else {
		switch (ast->children) {
			case 1:
				return zend_ast_create_unary(
					ast->kind,
					zend_ast_copy((&ast->u.child)[0]));
			case 2:
				return zend_ast_create_binary(
					ast->kind,
					zend_ast_copy((&ast->u.child)[0]),
					zend_ast_copy((&ast->u.child)[1]));
			case 3:
				return zend_ast_create_ternary(
					ast->kind,
					zend_ast_copy((&ast->u.child)[0]),
					zend_ast_copy((&ast->u.child)[1]),
					zend_ast_copy((&ast->u.child)[2]));
		}
	}
	return NULL;
}

ZEND_API void zend_ast_destroy(zend_ast *ast)
{
	int i;

	if (ast->kind == ZEND_CONST) {
		zval_dtor(ast->u.val);
	} else {
		for (i = 0; i < ast->children; i++) {
			if ((&ast->u.child)[i]) {
				zend_ast_destroy((&ast->u.child)[i]);
			}
		}
	}
	efree(ast);
}

static int zend_ast_kind_is_terminal(zend_ast_kind kind)
{
	return kind == ZEND_CONST;	
}

static const char *zend_ast_stringize_kind(zend_ast_kind kind)
{
	const char *retval = "(unknown)";
	switch (kind) {
	case ZEND_CONST:
		return "ZEND_CONST";
	case ZEND_BOOL_AND:
		return "ZEND_BOOL_AND";
	case ZEND_BOOL_OR:
		return "ZEND_BOOL_OR";
	case ZEND_SELECT:
		return "ZEND_SELECT";
	case ZEND_UNARY_PLUS:
		return "ZEND_UNARY_PLUS";
	case ZEND_UNARY_MINUS:
		return "ZEND_UMARY_MINUS";
	default:
		if (kind < 255) {
			return zend_get_opcode_name(kind);
		}
	}
	return retval;
}

typedef struct _zend_ast_wrapper {
	zend_object zo;
	zend_ast *ast;
	zend_ast *root;
	zend_object_handle root_handle;
} zend_ast_wrapper;

ZEND_API zend_class_entry *zend_ast_wrapper_ce;

static zend_ast_wrapper *zend_ast_wrapper_fetch(zval *zv TSRMLS_DC)
{
	return (zend_ast_wrapper *)zend_object_store_get_object(zv TSRMLS_CC);
}

static zval *zend_ast_wrapper_create_child(zend_ast_wrapper *ast_wrapper, zval *zv_ast_wrapper, zend_ast *ast_child TSRMLS_DC)
{
	zval *retval;
	ALLOC_INIT_ZVAL(retval);
	Z_TYPE_P(retval) = IS_OBJECT;
	Z_OBJVAL_P(retval) = zend_ast_wrapper_create_object(
		zend_ast_wrapper_ce,
		ast_child,
		ast_wrapper->root ? ast_wrapper->root: ast_wrapper->ast,
		ast_wrapper->root ? ast_wrapper->root_handle: Z_OBJ_HANDLE_P(zv_ast_wrapper)
	);
	return retval;
}

static zval *zend_ast_wrapper_property_read(zval *zv, zval *member, int type, const zend_literal *key TSRMLS_DC)
{
	zval *retval = NULL;
	zend_ast_wrapper *ast_wrapper = zend_ast_wrapper_fetch(zv TSRMLS_CC);
	zval tmp_zv;
	{
		if (Z_TYPE_P(member) != IS_STRING) {
			tmp_zv = *member;
			zval_copy_ctor(&tmp_zv);
			convert_to_string(&tmp_zv);
			member = &tmp_zv;
		}
	}

	if (strcmp(Z_STRVAL_P(member), "kind") == 0) {
		ALLOC_INIT_ZVAL(retval);
		Z_TYPE_P(retval) = IS_LONG;
		Z_LVAL_P(retval) = ast_wrapper->ast->kind;
	}

	if (strcmp(Z_STRVAL_P(member), "value") == 0) {
		if (zend_ast_kind_is_terminal(ast_wrapper->ast->kind)) {
			if (IS_CONSTANT_TYPE(Z_TYPE_P(ast_wrapper->ast->u.val))) {
				ALLOC_INIT_ZVAL(retval);
				*retval = *ast_wrapper->ast->u.val;
				Z_TYPE_P(retval) = IS_STRING;
				zval_copy_ctor(retval);
				zval_set_refcount_p(retval, 1);
			} else {
				zval_addref_p(ast_wrapper->ast->u.val);
				retval = ast_wrapper->ast->u.val;
			}
		} else {
			zval_addref_p(&EG(uninitialized_zval));
			retval = &EG(uninitialized_zval);
		}
	}

	if (strcmp(Z_STRVAL_P(member), "named") == 0) {
		ALLOC_INIT_ZVAL(retval);
		ZVAL_BOOL(retval, zend_ast_kind_is_terminal(ast_wrapper->ast->kind) && IS_CONSTANT_TYPE(Z_TYPE_P(ast_wrapper->ast->u.val)));
	}
out:
	if (&tmp_zv == member) {
		zval_dtor(&tmp_zv);
	}
	return retval;
}

static int zend_ast_wrapper_property_exists(zval *zv, zval *member, int check_empty, const zend_literal *key TSRMLS_DC)
{
	int retval = 0;
	zend_ast_wrapper *ast_wrapper = zend_ast_wrapper_fetch(zv TSRMLS_CC);
	zval tmp_zv;
	{
		if (Z_TYPE_P(member) != IS_STRING) {
			tmp_zv = *member;
			zval_copy_ctor(&tmp_zv);
			convert_to_string(&tmp_zv);
			member = &tmp_zv;
		}
	}

	if (strcmp(Z_STRVAL_P(member), "kind") == 0) {
		retval = 1;
		goto out;
	}
	if (strcmp(Z_STRVAL_P(member), "value") == 0) {
		retval = 1;
		goto out;
	}
	if (strcmp(Z_STRVAL_P(member), "named") == 0) {
		retval = 1;
		goto out;
	}
out:
	if (&tmp_zv == member) {
		zval_dtor(&tmp_zv);
	}
	return retval;
}

static zval *zend_ast_wrapper_dimension_read(zval *zv, zval *offset, int type TSRMLS_DC)
{
	zval *retval = NULL;
	zval tmp_zv;
	zend_ast_wrapper *ast_wrapper = zend_ast_wrapper_fetch(zv TSRMLS_CC);

	if (Z_TYPE_P(offset) != IS_LONG) {
		tmp_zv = *offset;
		zval_copy_ctor(&tmp_zv);
		offset = &tmp_zv;
		convert_to_long(offset);
	}
	if (Z_LVAL_P(offset) < 0 || Z_LVAL_P(offset) >= ast_wrapper->ast->children) {
		zend_error(E_WARNING, "Index of out bounds: %ld", Z_LVAL_P(offset));
		goto out;
	}
	retval = zend_ast_wrapper_create_child(ast_wrapper, zv, (&ast_wrapper->ast->u.child)[Z_LVAL_P(offset)]);
out:
	if (offset == &tmp_zv) {
		zval_dtor(&tmp_zv);
	}
	return retval;
}

static int zend_ast_wrapper_dimension_exists(zval *zv, zval *offset, int check_empty TSRMLS_DC)
{
	int retval = 0;
	zval tmp_zv;

	zend_ast_wrapper *ast_wrapper = zend_ast_wrapper_fetch(zv TSRMLS_CC);
	if (Z_TYPE_P(offset) != IS_LONG) {
		tmp_zv = *offset;
		zval_copy_ctor(&tmp_zv);
		offset = &tmp_zv;
		convert_to_long(offset);
	}
	if (Z_LVAL_P(offset) >= 0 && Z_LVAL_P(offset) < ast_wrapper->ast->children) {
		retval = 1;
	}
out:
	if (offset == &tmp_zv) {
		zval_dtor(&tmp_zv);
	}
	return retval;
}

static int zend_ast_wrapper_compare_objects(zval *zv_lhs, zval *zv_rhs TSRMLS_DC)
{
	zend_ast_wrapper *ast_wrapper_lhs = zend_ast_wrapper_fetch(zv_lhs),
	                 *ast_wrapper_rhs = zend_ast_wrapper_fetch(zv_rhs);
	return ast_wrapper_lhs->ast == ast_wrapper_rhs->ast;
}

static int zend_ast_wrapper_dimension_count(zval *zv, long *count TSRMLS_DC)
{
	zend_ast_wrapper *ast_wrapper = zend_ast_wrapper_fetch(zv);
	*count = ast_wrapper->ast->children;
	return SUCCESS;
}

static HashTable *zend_ast_wrapper_debug_info(zval *zv, int *is_temp TSRMLS_DC)
{
	zend_ast_wrapper *ast_wrapper = zend_ast_wrapper_fetch(zv);
	HashTable *retval;
	zval *kind, *children;
	int i;
	*is_temp = 1;
	ALLOC_HASHTABLE(retval);
	ALLOC_INIT_ZVAL(kind);
	ALLOC_INIT_ZVAL(children);
	zend_hash_init(retval, 2, NULL, ZVAL_PTR_DTOR, 0);
	array_init(children);
	ZVAL_STRING(kind, zend_ast_stringize_kind(ast_wrapper->ast->kind), 1);
	for (i = 0; i < ast_wrapper->ast->children; i++) {
		add_next_index_zval(children, zend_ast_wrapper_create_child(ast_wrapper, zv, (&ast_wrapper->ast->u.child)[i] TSRMLS_CC));
	}
	zend_hash_add(retval, "kind", sizeof("kind"), (void *)&kind, sizeof(zval *), NULL);
	zend_hash_add(retval, "(children)", sizeof("(children)"), (void *)&children, sizeof(zval *), NULL);
	if (zend_ast_kind_is_terminal(ast_wrapper->ast->kind)) {
		zval *value = NULL;
		zval *named;
		ALLOC_INIT_ZVAL(named);
		Z_TYPE_P(named) = IS_BOOL;
		Z_LVAL_P(named) = 0;
		if (IS_CONSTANT_TYPE(Z_TYPE_P(ast_wrapper->ast->u.val))) {
			ALLOC_ZVAL(value);
			*value = *ast_wrapper->ast->u.val;
			Z_TYPE_P(value) = IS_STRING;
			zval_copy_ctor(value);
			zval_set_refcount_p(value, 1);
		Z_LVAL_P(named) = 1;
		} else {
			zval_addref_p(ast_wrapper->ast->u.val);
			value = ast_wrapper->ast->u.val;
		}
		zend_hash_add(retval, "value", sizeof("value"), (void *)&value, sizeof(zval *), NULL);
		zend_hash_add(retval, "named", sizeof("named"), (void *)&named, sizeof(zval *), NULL);
	}
	return retval;
}

static const zend_function_entry zend_ast_wrapper_functions[] = { ZEND_FE_END };
static zend_object_handlers zend_ast_wrapper_object_handlers = {
	ZEND_OBJECTS_STORE_HANDLERS,
	zend_ast_wrapper_property_read,    /* property_read */
	NULL,                              /* property_write */
	zend_ast_wrapper_dimension_read,   /* dimension_read */
	NULL,                              /* dimension_write */
	NULL,                              /* property_get_addr */
	NULL,                              /* get */
	NULL,                              /* set */
	zend_ast_wrapper_property_exists,  /* has_property */
	NULL,                              /* unset_property */
	zend_ast_wrapper_dimension_exists, /* has_dimension */
	NULL,                              /* unset_dimension */
	NULL,                              /* get_properties */
	NULL,                              /* get_method */
	NULL,                              /* call_method */
	NULL,                              /* get_constructor */
	NULL,                              /* get_class_entry */
	NULL,                              /* get_class_name */
	zend_ast_wrapper_compare_objects,  /* compare_objects */
	NULL,                              /* cast_object */
	zend_ast_wrapper_dimension_count,  /* count_elements */
	zend_ast_wrapper_debug_info,       /* get_debug_info */
	NULL,                              /* get_closure */
	NULL,                              /* get_gc */
	NULL,                              /* do_operation */
	NULL                               /* compare */
};

static void zend_ast_wrapper_dtor(void *_ast_wrapper, zend_object_handle handle TSRMLS_DC)
{
	zend_ast_wrapper *ast_wrapper = _ast_wrapper;
	if (!ast_wrapper->root) {
		zend_ast_destroy(ast_wrapper->ast);
	} else {
		zend_objects_store_del_ref_by_handle_ex(ast_wrapper->root_handle, &zend_ast_wrapper_object_handlers TSRMLS_CC);
	}
}

static void zend_ast_wrapper_ctor(zend_ast_wrapper *ast_wrapper, zend_class_entry *ce, zend_ast *ast, zend_ast *root, zend_object_handle root_handle TSRMLS_DC)
{
	zend_object_std_init(&ast_wrapper->zo, ce TSRMLS_CC);
	ast_wrapper->ast = ast;
	ast_wrapper->root = root;
	ast_wrapper->root_handle = root_handle;
	if (ast_wrapper->root_handle) {
		zend_objects_store_add_ref_by_handle(ast_wrapper->root_handle TSRMLS_CC);
	}
}

static void zend_ast_wrapper_free_storage(void *_ast_wrapper TSRMLS_DC)
{
	efree(_ast_wrapper);
}

zend_object_value zend_ast_wrapper_create_object(zend_class_entry *ce, zend_ast *ast, zend_ast *root, zend_object_handle root_handle TSRMLS_DC)
{
	zend_ast_wrapper *ast_wrapper = emalloc(sizeof(*ast_wrapper));
	zend_ast_wrapper_ctor(ast_wrapper, ce, ast, root, root_handle TSRMLS_CC);
	zend_object_value retval = {
		zend_objects_store_put(ast_wrapper, zend_ast_wrapper_dtor, (zend_objects_free_object_storage_t)zend_ast_wrapper_free_storage, NULL TSRMLS_CC),
		&zend_ast_wrapper_object_handlers
	};
	return retval;
}

static zend_object_value zend_ast_wrapper_create_object_default(zend_class_entry *ce TSRMLS_DC)
{
	return zend_ast_wrapper_create_object(ce, NULL, NULL, 0 TSRMLS_CC);
}

void zend_register_zend_ast_wrapper_ce(TSRMLS_D)
{
	zend_class_entry tmp_ce, *ce;
	zend_object_handlers *std_handlers = zend_get_std_object_handlers();
	INIT_CLASS_ENTRY(tmp_ce, "ZendASTWrapper", zend_ast_wrapper_functions);
	ce = zend_register_internal_class(&tmp_ce TSRMLS_CC);
	ce->ce_flags |= ZEND_ACC_FINAL_CLASS;
	ce->create_object = zend_ast_wrapper_create_object_default;
	ce->serialize     = zend_class_serialize_deny;
	ce->unserialize   = zend_class_unserialize_deny;
	zend_ast_wrapper_object_handlers.get_class_entry = std_handlers->get_class_entry;
	zend_ast_wrapper_object_handlers.get_class_name = std_handlers->get_class_name;
	zend_ast_wrapper_ce = ce;
}
