/* Generated by re2c 0.5 on Thu May 20 13:55:15 2004 */
#line 1 "/home/george/src/pecl/pdo/pdo_sql_parser.re"
/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2004 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.0 of the PHP license,       |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_0.txt.                                  |
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

#define PDO_PARSER_TEXT 1
#define PDO_PARSER_BIND 2
#define PDO_PARSER_BIND_POS 3
#define PDO_PARSER_EOI 4

#define RET(i) {s->cur = cursor; return i; }

#define YYCTYPE         char
#define YYCURSOR        cursor
#define YYLIMIT         s->lim
#define YYMARKER        s->ptr
#define YYFILL(n)

typedef struct Scanner {
	char 	*lim, *ptr, *cur, *tok;
} Scanner;

static int scan(Scanner *s) 
{
	char *cursor = s->cur;
	std:
		s->tok = cursor;
	#line 54


	{
	YYCTYPE yych;
	unsigned int yyaccept;
	static unsigned char yybm[] = {
	  0, 168, 168, 168, 168, 168, 168, 168, 
	168, 168, 168, 168, 168, 168, 168, 168, 
	168, 168, 168, 168, 168, 168, 168, 168, 
	168, 168, 168, 168, 168, 168, 168, 168, 
	168, 168,   0, 168, 168, 168, 168, 192, 
	168, 168, 168, 168, 168, 168, 168, 168, 
	184, 184, 184, 184, 184, 184, 184, 184, 
	184, 184, 160, 168, 168, 168, 168, 160, 
	168, 184, 184, 184, 184, 184, 184, 184, 
	184, 184, 184, 184, 184, 184, 184, 184, 
	184, 184, 184, 184, 184, 184, 184, 184, 
	184, 184, 184, 168,   8, 168, 168, 184, 
	168, 184, 184, 184, 184, 184, 184, 184, 
	184, 184, 184, 184, 184, 184, 184, 184, 
	184, 184, 184, 184, 184, 184, 184, 184, 
	184, 184, 184, 168, 168, 168, 168, 168, 
	168, 168, 168, 168, 168, 168, 168, 168, 
	168, 168, 168, 168, 168, 168, 168, 168, 
	168, 168, 168, 168, 168, 168, 168, 168, 
	168, 168, 168, 168, 168, 168, 168, 168, 
	168, 168, 168, 168, 168, 168, 168, 168, 
	168, 168, 168, 168, 168, 168, 168, 168, 
	168, 168, 168, 168, 168, 168, 168, 168, 
	168, 168, 168, 168, 168, 168, 168, 168, 
	168, 168, 168, 168, 168, 168, 168, 168, 
	168, 168, 168, 168, 168, 168, 168, 168, 
	168, 168, 168, 168, 168, 168, 168, 168, 
	168, 168, 168, 168, 168, 168, 168, 168, 
	168, 168, 168, 168, 168, 168, 168, 168, 
	168, 168, 168, 168, 168, 168, 168, 168, 
	168, 168, 168, 168, 168, 168, 168, 168, 
	168, 168, 168, 168, 168, 168, 168, 168, 
	};
	goto yy0;
yy1:	++YYCURSOR;
yy0:
	if((YYLIMIT - YYCURSOR) < 2) YYFILL(2);
	yych = *YYCURSOR;
	if(yybm[0+yych] & 8)	goto yy8;
	if(yych <= '\000')	goto yy11;
	if(yych <= '&')	goto yy2;
	if(yych <= '\'')	goto yy4;
	if(yych <= '>')	goto yy5;
	goto yy6;
yy2:	yyaccept = 0;
	yych = *(YYMARKER = ++YYCURSOR);
	if(yych >= '\001')	goto yy24;
yy3:
#line 61
	{ RET(PDO_PARSER_TEXT); }
yy4:	yyaccept = 0;
	yych = *(YYMARKER = ++YYCURSOR);
	if(yych <= '\000')	goto yy3;
	if(yych == '"')	goto yy3;
	goto yy17;
yy5:	yych = *++YYCURSOR;
	if(yybm[0+yych] & 16)	goto yy13;
	goto yy3;
yy6:	yych = *++YYCURSOR;
yy7:
#line 60
	{ RET(PDO_PARSER_BIND_POS); }
yy8:	++YYCURSOR;
	if(YYLIMIT == YYCURSOR) YYFILL(1);
	yych = *YYCURSOR;
yy9:	if(yybm[0+yych] & 8)	goto yy8;
yy10:
#line 62
	{ RET(PDO_PARSER_TEXT); }
yy11:	yych = *++YYCURSOR;
yy12:
#line 63
	{ RET(PDO_PARSER_EOI); }
yy13:	++YYCURSOR;
	if(YYLIMIT == YYCURSOR) YYFILL(1);
	yych = *YYCURSOR;
yy14:	if(yybm[0+yych] & 16)	goto yy13;
yy15:
#line 59
	{ RET(PDO_PARSER_BIND); }
yy16:	++YYCURSOR;
	if(YYLIMIT == YYCURSOR) YYFILL(1);
	yych = *YYCURSOR;
yy17:	if(yybm[0+yych] & 32)	goto yy16;
	if(yych <= '&')	goto yy18;
	if(yych <= '\'')	goto yy19;
	goto yy22;
yy18:	YYCURSOR = YYMARKER;
	switch(yyaccept){
	case 1:	goto yy21;
	case 0:	goto yy3;
	}
yy19:	yyaccept = 1;
	YYMARKER = ++YYCURSOR;
	if(YYLIMIT == YYCURSOR) YYFILL(1);
	yych = *YYCURSOR;
yy20:	if(yybm[0+yych] & 32)	goto yy16;
	if(yych <= '&')	goto yy21;
	if(yych <= '\'')	goto yy19;
	goto yy22;
yy21:
#line 58
	{ RET(PDO_PARSER_TEXT); }
yy22:	++YYCURSOR;
	if(YYLIMIT == YYCURSOR) YYFILL(1);
	yych = *YYCURSOR;
	if(yych == '\'')	goto yy16;
	goto yy18;
yy23:	++YYCURSOR;
	if(YYLIMIT == YYCURSOR) YYFILL(1);
	yych = *YYCURSOR;
yy24:	if(yybm[0+yych] & 128)	goto yy23;
	if(yych <= '\000')	goto yy18;
	if(yych <= '[')	goto yy26;
yy25:	++YYCURSOR;
	if(YYLIMIT == YYCURSOR) YYFILL(1);
	yych = *YYCURSOR;
	if(yych == '"')	goto yy23;
	goto yy18;
yy26:	yych = *++YYCURSOR;
yy27:
#line 57
	{ RET(PDO_PARSER_TEXT); }
}
#line 64
	
}

int pdo_parse_params(pdo_stmt_t *stmt, char *inquery, int inquery_len, char **outquery, 
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
	s.lim = inquery + inquery_len;
	while((t = scan(&s)) != PDO_PARSER_EOI) {
		if(t == PDO_PARSER_TEXT) {
			memcpy(ptr, s.tok, s.cur - s.tok);
			ptr += (s.cur - s.tok);
			*outquery_len += (s.cur - s.tok);
		}
		else if(t == PDO_PARSER_BIND) {
			char crutch;
			if(!params) { 
				/* error */
				efree(*outquery);
				*outquery = NULL;
				return (int) (s.cur - inquery);
			}
			/* lookup bind first via hash and then index */
			/* stupid keys need to be null-terminated, even though we know their length */
			crutch  = s.tok[s.cur-s.tok];
			s.tok[s.cur-s.tok] = '\0';
			if((SUCCESS == zend_hash_find(params, s.tok, s.cur-s.tok + 1,(void **)&param))  
			    ||
			   (SUCCESS == zend_hash_index_find(params, bindno, (void **)&param))) 
			{
				char *quotedstr;
				int quotedstrlen;
				/* restore the in-string key, doesn't need null-termination here */
				s.tok[s.cur-s.tok] = crutch;
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

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker ft=c
 * vim<600: noet sw=4 ts=4
 */
