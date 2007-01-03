/* Generated by re2c 0.10.4 on Wed Jan  3 22:04:03 2007 */
#line 1 "ext/pdo/pdo_sql_parser.re"
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
  | Author: George Schlossnagle <george@omniti.com>                      |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#include "php.h"
#include "php_pdo_driver.h"
#include "php_pdo_int.h"

#define PDO_PARSER_TEXT 1
#define PDO_PARSER_BIND 2
#define PDO_PARSER_BIND_POS 3
#define PDO_PARSER_EOI 4

#define RET(i) {s->cur = cursor; return i; }

#define YYCTYPE         unsigned char
#define YYCURSOR        cursor
#define YYLIMIT         cursor
#define YYMARKER        s->ptr
#define YYFILL(n)

typedef struct Scanner {
	char 	*ptr, *cur, *tok;
} Scanner;

static int scan(Scanner *s) 
{
	char *cursor = s->cur;

	s->tok = cursor;
	#line 53 "ext/pdo/pdo_sql_parser.re"


	{
	static unsigned char yybm[] = {
		160, 162, 162, 162, 162, 162, 162, 162, 
		162, 162, 162, 162, 162, 162, 162, 162, 
		162, 162, 162, 162, 162, 162, 162, 162, 
		162, 162, 162, 162, 162, 162, 162, 162, 
		162, 162,  52, 162, 162, 162, 162, 196, 
		162, 162, 162, 162, 162, 162, 162, 162, 
		170, 170, 170, 170, 170, 170, 170, 170, 
		170, 170, 244, 162, 162, 162, 162, 244, 
		162, 170, 170, 170, 170, 170, 170, 170, 
		170, 170, 170, 170, 170, 170, 170, 170, 
		170, 170, 170, 170, 170, 170, 170, 170, 
		170, 170, 170, 162, 162, 162, 162, 170, 
		162, 170, 170, 170, 170, 170, 170, 170, 
		170, 170, 170, 170, 170, 170, 170, 170, 
		170, 170, 170, 170, 170, 170, 170, 170, 
		170, 170, 170, 162, 162, 162, 162, 162, 
		162, 162, 162, 162, 162, 162, 162, 162, 
		162, 162, 162, 162, 162, 162, 162, 162, 
		162, 162, 162, 162, 162, 162, 162, 162, 
		162, 162, 162, 162, 162, 162, 162, 162, 
		162, 162, 162, 162, 162, 162, 162, 162, 
		162, 162, 162, 162, 162, 162, 162, 162, 
		162, 162, 162, 162, 162, 162, 162, 162, 
		162, 162, 162, 162, 162, 162, 162, 162, 
		162, 162, 162, 162, 162, 162, 162, 162, 
		162, 162, 162, 162, 162, 162, 162, 162, 
		162, 162, 162, 162, 162, 162, 162, 162, 
		162, 162, 162, 162, 162, 162, 162, 162, 
		162, 162, 162, 162, 162, 162, 162, 162, 
		162, 162, 162, 162, 162, 162, 162, 162, 
		162, 162, 162, 162, 162, 162, 162, 162, 
		162, 162, 162, 162, 162, 162, 162, 162, 
	};

#line 89 "ext/pdo/pdo_sql_parser.c"
	{
		YYCTYPE yych;

		if((YYLIMIT - YYCURSOR) < 3) YYFILL(3);
		yych = *YYCURSOR;
		if(yybm[0+yych] & 2) {
			goto yy8;
		}
		if(yych <= 0x00) goto yy11;
		if(yych <= '&') goto yy2;
		if(yych <= '\'') goto yy4;
		if(yych <= '>') goto yy5;
		goto yy6;
yy2:
		yych = *++YYCURSOR;
		if(yybm[0+yych] & 64) {
			goto yy28;
		}
		if(yych == '"') goto yy26;
		goto yy30;
yy3:
#line 61 "ext/pdo/pdo_sql_parser.re"
		{ RET(PDO_PARSER_TEXT); }
#line 113 "ext/pdo/pdo_sql_parser.c"
yy4:
		yych = *++YYCURSOR;
		if(yybm[0+yych] & 16) {
			goto yy19;
		}
		if(yych == '\'') goto yy21;
		goto yy23;
yy5:
		yych = *++YYCURSOR;
		if(yybm[0+yych] & 4) {
			goto yy13;
		}
		if(yych <= 'Z') {
			if(yych <= '/') goto yy3;
			if(yych <= ':') goto yy16;
			if(yych <= '@') goto yy3;
			goto yy16;
		} else {
			if(yych <= '_') {
				if(yych <= '^') goto yy3;
				goto yy16;
			} else {
				if(yych <= '`') goto yy3;
				if(yych <= 'z') goto yy16;
				goto yy3;
			}
		}
yy6:
		++YYCURSOR;
		if(yybm[0+(yych = *YYCURSOR)] & 4) {
			goto yy13;
		}
#line 60 "ext/pdo/pdo_sql_parser.re"
		{ RET(PDO_PARSER_BIND_POS); }
#line 148 "ext/pdo/pdo_sql_parser.c"
yy8:
		++YYCURSOR;
		if(YYLIMIT == YYCURSOR) YYFILL(1);
		yych = *YYCURSOR;
		if(yybm[0+yych] & 2) {
			goto yy8;
		}
#line 62 "ext/pdo/pdo_sql_parser.re"
		{ RET(PDO_PARSER_TEXT); }
#line 158 "ext/pdo/pdo_sql_parser.c"
yy11:
		++YYCURSOR;
#line 63 "ext/pdo/pdo_sql_parser.re"
		{ RET(PDO_PARSER_EOI); }
#line 163 "ext/pdo/pdo_sql_parser.c"
yy13:
		++YYCURSOR;
		if(YYLIMIT == YYCURSOR) YYFILL(1);
		yych = *YYCURSOR;
		if(yybm[0+yych] & 4) {
			goto yy13;
		}
#line 58 "ext/pdo/pdo_sql_parser.re"
		{ RET(PDO_PARSER_TEXT); }
#line 173 "ext/pdo/pdo_sql_parser.c"
yy16:
		++YYCURSOR;
		if(YYLIMIT == YYCURSOR) YYFILL(1);
		yych = *YYCURSOR;
		if(yybm[0+yych] & 8) {
			goto yy16;
		}
#line 59 "ext/pdo/pdo_sql_parser.re"
		{ RET(PDO_PARSER_BIND); }
#line 183 "ext/pdo/pdo_sql_parser.c"
yy19:
		if((YYLIMIT - YYCURSOR) < 2) YYFILL(2);
		yych = *YYCURSOR;
		if(yybm[0+yych] & 16) {
			goto yy19;
		}
		if(yych != '\'') goto yy23;
yy21:
		++YYCURSOR;
		if(yybm[0+(yych = *YYCURSOR)] & 4) {
			goto yy13;
		}
yy22:
#line 57 "ext/pdo/pdo_sql_parser.re"
		{ RET(PDO_PARSER_TEXT); }
#line 199 "ext/pdo/pdo_sql_parser.c"
yy23:
		++YYCURSOR;
		if(YYLIMIT == YYCURSOR) YYFILL(1);
		yych = *YYCURSOR;
		if(yybm[0+yych] & 32) {
			goto yy23;
		}
		yych = *++YYCURSOR;
		goto yy22;
yy26:
		++YYCURSOR;
		if(yybm[0+(yych = *YYCURSOR)] & 4) {
			goto yy13;
		}
yy27:
#line 56 "ext/pdo/pdo_sql_parser.re"
		{ RET(PDO_PARSER_TEXT); }
#line 217 "ext/pdo/pdo_sql_parser.c"
yy28:
		if((YYLIMIT - YYCURSOR) < 2) YYFILL(2);
		yych = *YYCURSOR;
		if(yybm[0+yych] & 64) {
			goto yy28;
		}
		if(yych == '"') goto yy26;
yy30:
		++YYCURSOR;
		if(YYLIMIT == YYCURSOR) YYFILL(1);
		yych = *YYCURSOR;
		if(yybm[0+yych] & 128) {
			goto yy30;
		}
		++YYCURSOR;
		yych = *YYCURSOR;
		goto yy27;
	}
}
#line 64 "ext/pdo/pdo_sql_parser.re"
	
}

struct placeholder {
	char *pos;
	int len;
	int bindno;
	int qlen;		/* quoted length of value */
	char *quoted;	/* quoted value */
	int freeq;
	struct placeholder *next;
};

PDO_API int pdo_parse_params(pdo_stmt_t *stmt, char *inquery, int inquery_len, 
	char **outquery, int *outquery_len TSRMLS_DC)
{
	Scanner s;
	char *ptr, *newbuffer;
	int t;
	int bindno = 0;
	int ret = 0;
	int newbuffer_len;
	HashTable *params;
	struct pdo_bound_param_data *param;
	int query_type = PDO_PLACEHOLDER_NONE;
	struct placeholder *placeholders = NULL, *placetail = NULL, *plc = NULL;

	ptr = *outquery;
	s.cur = inquery;

	/* phase 1: look for args */
	while((t = scan(&s)) != PDO_PARSER_EOI) {
		if (t == PDO_PARSER_BIND || t == PDO_PARSER_BIND_POS) {
			if (t == PDO_PARSER_BIND) {
				query_type |= PDO_PLACEHOLDER_NAMED;
			} else {
				query_type |= PDO_PLACEHOLDER_POSITIONAL;
			}

			plc = emalloc(sizeof(*plc));
			memset(plc, 0, sizeof(*plc));
			plc->next = NULL;
			plc->pos = s.tok;
			plc->len = s.cur - s.tok;
			plc->bindno = bindno++;

			if (placetail) {
				placetail->next = plc;
			} else {
				placeholders = plc;
			}
			placetail = plc;
		}
	}

	if (bindno == 0) {
		/* nothing to do; good! */
		return 0;
	}

	/* did the query make sense to me? */
	if (query_type == (PDO_PLACEHOLDER_NAMED|PDO_PLACEHOLDER_POSITIONAL)) {
		/* they mixed both types; punt */
		pdo_raise_impl_error(stmt->dbh, stmt, "HY093", "mixed named and positional parameters" TSRMLS_CC);
		ret = -1;
		goto clean_up;
	}

	if (stmt->supports_placeholders == query_type && !stmt->named_rewrite_template) {
		/* query matches native syntax */
		ret = 0;
		goto clean_up;
	}

	if (stmt->named_rewrite_template) {
		/* magic/hack.
		 * We we pretend that the query was positional even if
		 * it was named so that we fall into the
		 * named rewrite case below.  Not too pretty,
		 * but it works. */
		query_type = PDO_PLACEHOLDER_POSITIONAL;
	}
	
	params = stmt->bound_params;
	
	/* Do we have placeholders but no bound params */
	if (bindno && !params && stmt->supports_placeholders == PDO_PLACEHOLDER_NONE) {
		pdo_raise_impl_error(stmt->dbh, stmt, "HY093", "no parameters were bound" TSRMLS_CC);
		ret = -1;
		goto clean_up;
	}

	if (params && bindno != zend_hash_num_elements(params) && stmt->supports_placeholders == PDO_PLACEHOLDER_NONE) {
		pdo_raise_impl_error(stmt->dbh, stmt, "HY093", "number of bound variables does not match number of tokens" TSRMLS_CC);
		ret = -1;
		goto clean_up;
	}

	/* what are we going to do ? */
	
	if (stmt->supports_placeholders == PDO_PLACEHOLDER_NONE) {
		/* query generation */

		newbuffer_len = inquery_len;

		/* let's quote all the values */	
		for (plc = placeholders; plc; plc = plc->next) {
			if (query_type == PDO_PLACEHOLDER_POSITIONAL) {
				ret = zend_hash_index_find(params, plc->bindno, (void**) &param);
			} else {
				ret = zend_hash_find(params, plc->pos, plc->len, (void**) &param);
			}
			if (ret == FAILURE) {
				/* parameter was not defined */
				ret = -1;
				pdo_raise_impl_error(stmt->dbh, stmt, "HY093", "parameter was not defined" TSRMLS_CC);
				goto clean_up;
			}
			if (stmt->dbh->methods->quoter) {
				if (param->param_type == PDO_PARAM_LOB && Z_TYPE_P(param->parameter) == IS_RESOURCE) {
					php_stream *stm;

					php_stream_from_zval_no_verify(stm, &param->parameter);
					if (stm) {
						size_t len;
						char *buf = NULL;
					
						len = php_stream_copy_to_mem(stm, &buf, PHP_STREAM_COPY_ALL, 0);
						if (!stmt->dbh->methods->quoter(stmt->dbh, buf, len, &plc->quoted, &plc->qlen,
								param->param_type TSRMLS_CC)) {
							/* bork */
							ret = -1;
							strcpy(stmt->error_code, stmt->dbh->error_code);
							if (buf) {
								efree(buf);
							}
							goto clean_up;
						}
						if (buf) {
							efree(buf);
						}
					} else {
						pdo_raise_impl_error(stmt->dbh, stmt, "HY105", "Expected a stream resource" TSRMLS_CC);
						ret = -1;
						goto clean_up;
					}
					plc->freeq = 1;
				} else {
					switch (Z_TYPE_P(param->parameter)) {
						case IS_NULL:
							plc->quoted = "NULL";
							plc->qlen = sizeof("NULL")-1;
							plc->freeq = 0;
							break;

						case IS_LONG:
						case IS_DOUBLE:
							convert_to_string(param->parameter);
							plc->qlen = Z_STRLEN_P(param->parameter);
							plc->quoted = Z_STRVAL_P(param->parameter);
							plc->freeq = 0;
							break;

						case IS_BOOL:
							convert_to_long(param->parameter);
						default:
							convert_to_string(param->parameter);
							if (!stmt->dbh->methods->quoter(stmt->dbh, Z_STRVAL_P(param->parameter),
									Z_STRLEN_P(param->parameter), &plc->quoted, &plc->qlen,
									param->param_type TSRMLS_CC)) {
								/* bork */
								ret = -1;
								strcpy(stmt->error_code, stmt->dbh->error_code);
								goto clean_up;
							}
							plc->freeq = 1;
					}
				}
			} else {
				plc->quoted = Z_STRVAL_P(param->parameter);
				plc->qlen = Z_STRLEN_P(param->parameter);
			}
			newbuffer_len += plc->qlen;
		}

rewrite:
		/* allocate output buffer */
		newbuffer = emalloc(newbuffer_len + 1);
		*outquery = newbuffer;

		/* and build the query */
		plc = placeholders;
		ptr = inquery;

		do {
			t = plc->pos - ptr;
			if (t) {
				memcpy(newbuffer, ptr, t);
				newbuffer += t;
			}
			memcpy(newbuffer, plc->quoted, plc->qlen);
			newbuffer += plc->qlen;
			ptr = plc->pos + plc->len;

			plc = plc->next;
		} while (plc);

		t = (inquery + inquery_len) - ptr;
		if (t) {
			memcpy(newbuffer, ptr, t);
			newbuffer += t;
		}
		*newbuffer = '\0';
		*outquery_len = newbuffer - *outquery;

		ret = 1;
		goto clean_up;

	} else if (query_type == PDO_PLACEHOLDER_POSITIONAL) {
		/* rewrite ? to :pdoX */
		char idxbuf[32];
		const char *tmpl = stmt->named_rewrite_template ? stmt->named_rewrite_template : ":pdo%d";
		char *name;
		
		newbuffer_len = inquery_len;

		if (stmt->bound_param_map == NULL) {
			ALLOC_HASHTABLE(stmt->bound_param_map);
			zend_hash_init(stmt->bound_param_map, 13, NULL, NULL, 0);
		}

		for (plc = placeholders; plc; plc = plc->next) {
			int skip_map = 0;
			char *p;
			name = estrndup(plc->pos, plc->len);

			/* check if bound parameter is already available */
			if (!strcmp(name, "?") || zend_hash_find(stmt->bound_param_map, name, plc->len + 1, (void**) &p) == FAILURE) {
				snprintf(idxbuf, sizeof(idxbuf), tmpl, plc->bindno + 1);
			} else {
				memset(idxbuf, 0, sizeof(idxbuf));
				memcpy(idxbuf, p, sizeof(idxbuf));
				skip_map = 1;
			}

			plc->quoted = estrdup(idxbuf);
			plc->qlen = strlen(plc->quoted);
			plc->freeq = 1;
			newbuffer_len += plc->qlen;

			if (!skip_map && stmt->named_rewrite_template) {
				/* create a mapping */
				
				zend_hash_update(stmt->bound_param_map, name, plc->len + 1, idxbuf, plc->qlen + 1, NULL);
			}

			/* map number to name */
			zend_hash_index_update(stmt->bound_param_map, plc->bindno, idxbuf, plc->qlen + 1, NULL);
			
			efree(name);
		}
				
		goto rewrite;

	} else {
		/* rewrite :name to ? */
		
		newbuffer_len = inquery_len;
	
		if (stmt->bound_param_map == NULL) {
			ALLOC_HASHTABLE(stmt->bound_param_map);
			zend_hash_init(stmt->bound_param_map, 13, NULL, NULL, 0);
		}
		
		for (plc = placeholders; plc; plc = plc->next) {
			char *name;
			
			name = estrndup(plc->pos, plc->len);
			zend_hash_index_update(stmt->bound_param_map, plc->bindno, name, plc->len + 1, NULL);
			efree(name);
			plc->quoted = "?";
			plc->qlen = 1;
		}

		goto rewrite;
	}

clean_up:

	while (placeholders) {
		plc = placeholders;
		placeholders = plc->next;

		if (plc->freeq) {
			efree(plc->quoted);
		}

		efree(plc);
	}

	return ret;
}

#if 0
int old_pdo_parse_params(pdo_stmt_t *stmt, char *inquery, int inquery_len, char **outquery, 
		int *outquery_len TSRMLS_DC)
{
	Scanner s;
	char *ptr;
	int t;
	int bindno = 0;
	int newbuffer_len;
	int padding;
	HashTable *params = stmt->bound_params;
	struct pdo_bound_param_data *param;
	/* allocate buffer for query with expanded binds, ptr is our writing pointer */
	newbuffer_len = inquery_len;

	/* calculate the possible padding factor due to quoting */
	if(stmt->dbh->max_escaped_char_length) {
		padding = stmt->dbh->max_escaped_char_length;
	} else {
		padding = 3;
	}
	if(params) {
		zend_hash_internal_pointer_reset(params);
		while (SUCCESS == zend_hash_get_current_data(params, (void**)&param)) {
			if(param->parameter) {
				convert_to_string(param->parameter);
				/* accomodate a string that needs to be fully quoted
                   bind placeholders are at least 2 characters, so
                   the accomodate their own "'s
                */
				newbuffer_len += padding * Z_STRLEN_P(param->parameter);
			}
			zend_hash_move_forward(params);
		}
	}
	*outquery = (char *) emalloc(newbuffer_len + 1);
	*outquery_len = 0;

	ptr = *outquery;
	s.cur = inquery;
	while((t = scan(&s)) != PDO_PARSER_EOI) {
		if(t == PDO_PARSER_TEXT) {
			memcpy(ptr, s.tok, s.cur - s.tok);
			ptr += (s.cur - s.tok);
			*outquery_len += (s.cur - s.tok);
		}
		else if(t == PDO_PARSER_BIND) {
			if(!params) { 
				/* error */
				efree(*outquery);
				*outquery = NULL;
				return (int) (s.cur - inquery);
			}
			/* lookup bind first via hash and then index */
			/* stupid keys need to be null-terminated, even though we know their length */
			if((SUCCESS == zend_hash_find(params, s.tok, s.cur-s.tok,(void **)&param))  
			    ||
			   (SUCCESS == zend_hash_index_find(params, bindno, (void **)&param))) 
			{
				char *quotedstr;
				int quotedstrlen;
				/* restore the in-string key, doesn't need null-termination here */
				/* currently everything is a string here */
				
				/* quote the bind value if necessary */
				if(stmt->dbh->methods->quoter(stmt->dbh, Z_STRVAL_P(param->parameter), 
					Z_STRLEN_P(param->parameter), &quotedstr, &quotedstrlen TSRMLS_CC))
				{
					memcpy(ptr, quotedstr, quotedstrlen);
					ptr += quotedstrlen;
					*outquery_len += quotedstrlen;
					efree(quotedstr);
				} else {
					memcpy(ptr, Z_STRVAL_P(param->parameter), Z_STRLEN_P(param->parameter));
					ptr += Z_STRLEN_P(param->parameter);
					*outquery_len += (Z_STRLEN_P(param->parameter));
				}
			}
			else {
				/* error and cleanup */
				efree(*outquery);
				*outquery = NULL;
				return (int) (s.cur - inquery);
			}
			bindno++;
		}
		else if(t == PDO_PARSER_BIND_POS) {
			if(!params) { 
				/* error */
				efree(*outquery);
				*outquery = NULL;
				return (int) (s.cur - inquery);
			}
			/* lookup bind by index */
			if(SUCCESS == zend_hash_index_find(params, bindno, (void **)&param)) 
			{
				char *quotedstr;
				int quotedstrlen;
				/* currently everything is a string here */
				
				/* quote the bind value if necessary */
				if(stmt->dbh->methods->quoter(stmt->dbh, Z_STRVAL_P(param->parameter), 
					Z_STRLEN_P(param->parameter), &quotedstr, &quotedstrlen TSRMLS_CC))
				{
					memcpy(ptr, quotedstr, quotedstrlen);
					ptr += quotedstrlen;
					*outquery_len += quotedstrlen;
					efree(quotedstr);
				} else {
					memcpy(ptr, Z_STRVAL_P(param->parameter), Z_STRLEN_P(param->parameter));
					ptr += Z_STRLEN_P(param->parameter);
					*outquery_len += (Z_STRLEN_P(param->parameter));
				}
			}
			else {
				/* error and cleanup */
				efree(*outquery);
				*outquery = NULL;
				return (int) (s.cur - inquery);
			}
			bindno++;
		}
	}	
	*ptr = '\0';
	return 0;
}
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker ft=c
 * vim<600: noet sw=4 ts=4
 */
