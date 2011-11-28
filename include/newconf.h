/* This code is in the public domain.
 * $Nightmare: nightmare/include/config.h,v 1.32.2.2.2.2 2002/07/02 03:41:28 ejb Exp $
 * $Id: newconf.h 26094 2008-09-19 15:33:46Z androsyn $
 */

#ifndef _NEWCONF_H_INCLUDED
#define _NEWCONF_H_INCLUDED

extern FILE *conf_fbfile_in;

#define CF_QSTRING	0x01
#define CF_INT		0x02
#define CF_STRING	0x03
#define CF_TIME		0x04
#define CF_YESNO	0x05
#define CF_LIST		0x06
#define CF_ONE		0x07

#define CF_MTYPE	0xFF

#define CF_FLIST	0x1000
#define CF_MFLAG	0xFF00



typedef struct conf_parm_t_stru
{
	struct conf_parm_t_stru *next;
	int type;
	union
	{
		char *string;
		int number;
		struct conf_parm_t_stru *list;
	}
	v;
}
conf_parm_t;

struct _confentry;

extern int lineno;
extern char linebuf[];

extern int yyparse(void);


typedef struct _confentry
{
	rb_dlink_node node;
	char *entryname;
	long number;
	char *string;
	rb_dlink_list flist;
	unsigned int line;
	char *filename;
	int type;
} confentry_t;

typedef struct _conf
{
	rb_dlink_node node;
	char *confname;
	char *subname;
	rb_dlink_list entries;
	char *filename;
	unsigned int line;
} conf_t;

struct conf_items;

typedef void CONF_CB(confentry_t *, conf_t *, struct conf_items *);

struct conf_items
{
	const char *c_name;
	int type;
	CONF_CB *cb_func;
	int len;
	void *data;
};



/* parser/lexer support functions */
int conf_yy_fatal_error(const char *msg);
void conf_yy_report_error(const char *msg);
void conf_report_warning(const char *format, ...);

void yyerror(const char *msg);
int conf_fgets(char *, int, FILE *);


void delete_all_conf(void);
int check_valid_blocks(void);
int check_valid_entries(void);

int read_config_file(const char *);
int conf_start_block(char *, char *);
int conf_end_block(void);
int conf_call_set(char *, conf_parm_t *, int);
void conf_report_error(const char *, ...);
void newconf_init(void);
int add_conf_item(const char *topconf, const char *name, int type, void (*func) (void *));
void add_all_conf_settings(void);
void load_conf_settings(void);
#endif
