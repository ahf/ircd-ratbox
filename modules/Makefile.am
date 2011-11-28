
AUTOMAKE_OPTIONS = foreign subdir-objects

prefix          = @prefix@
libcoredir      = @libdir@
modulesdir      = @moduledir@/autoload
coredir         = @moduledir@
servicesdir     = @moduledir@/autoload
libmodulesdir	= @moduledir@
INCLUDES = -I../libratbox/include -I../include -I../libltdl @SSL_INCLUDES@

AM_CFLAGS = $(WARNFLAGS)


if MINGW
EXTRA_FLAGS = -no-undefined -Wl,--enable-runtime-pseudo-reloc -export-symbols-regex '*'
endif


MODULE_FLAGS = $(EXTRA_FLAGS) -avoid-version 

if !STATIC_MODULES

if MINGW
MODULE_LIBS = ../libratbox/src/libratbox.la ../src/libcore.la @SSL_LIBS@ 
endif # MINGW





m_accept_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_admin_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_adminwall_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_away_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_capab_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_cap_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_close_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_cmessage_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_connect_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_dline_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_encap_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_gline_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_gungline_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_help_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_info_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_invite_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_ison_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_kline_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_knock_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_links_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_list_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_locops_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_lusers_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_map_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_monitor_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_motd_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_names_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_oper_la_LDFLAGS =  -module $(MODULE_FLAGS) @SSL_LIBS@
m_operspy_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_pass_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_ping_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_pong_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_post_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_rehash_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_restart_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_resv_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_set_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_stats_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_svinfo_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_tb_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_testline_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_testmask_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_time_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_topic_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_trace_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_unreject_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_user_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_userhost_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_version_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_wallops_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_who_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_whois_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_whowas_la_LDFLAGS =  -module $(MODULE_FLAGS)  
m_xline_la_LDFLAGS =  -module $(MODULE_FLAGS)  

m_accept_la_SOURCES =	m_accept.c
m_admin_la_SOURCES =	m_admin.c
m_adminwall_la_SOURCES= m_adminwall.c
m_away_la_SOURCES =	m_away.c
m_capab_la_SOURCES =	m_capab.c
m_cap_la_SOURCES =	m_cap.c
m_close_la_SOURCES =	m_close.c
m_cmessage_la_SOURCES =	m_cmessage.c
m_connect_la_SOURCES =	m_connect.c
m_dline_la_SOURCES =	m_dline.c
m_encap_la_SOURCES =	m_encap.c
m_gline_la_SOURCES =	m_gline.c
m_gungline_la_SOURCES =	m_gungline.c
m_help_la_SOURCES =	m_help.c
m_info_la_SOURCES =	m_info.c
m_invite_la_SOURCES =	m_invite.c
m_ison_la_SOURCES =	m_ison.c
m_kline_la_SOURCES =	m_kline.c
m_knock_la_SOURCES =	m_knock.c
m_links_la_SOURCES =	m_links.c
m_list_la_SOURCES =	m_list.c
m_locops_la_SOURCES =	m_locops.c
m_lusers_la_SOURCES =	m_lusers.c
m_map_la_SOURCES =	m_map.c
m_monitor_la_SOURCES =	m_monitor.c
m_motd_la_SOURCES =	m_motd.c
m_names_la_SOURCES =	m_names.c
m_oper_la_SOURCES =	m_oper.c
m_operspy_la_SOURCES =	m_operspy.c
m_pass_la_SOURCES =	m_pass.c
m_ping_la_SOURCES =	m_ping.c
m_pong_la_SOURCES =	m_pong.c
m_post_la_SOURCES =	m_post.c
m_rehash_la_SOURCES =	m_rehash.c
m_restart_la_SOURCES =	m_restart.c
m_resv_la_SOURCES =	m_resv.c
m_set_la_SOURCES =	m_set.c
m_stats_la_SOURCES =	m_stats.c
m_svinfo_la_SOURCES =	m_svinfo.c
m_tb_la_SOURCES =	m_tb.c
m_testline_la_SOURCES =	m_testline.c
m_testmask_la_SOURCES =	m_testmask.c
m_time_la_SOURCES =	m_time.c
m_topic_la_SOURCES =	m_topic.c
m_trace_la_SOURCES =	m_trace.c
m_unreject_la_SOURCES =	m_unreject.c
m_user_la_SOURCES =	m_user.c
m_userhost_la_SOURCES =	m_userhost.c
m_version_la_SOURCES =	m_version.c
m_wallops_la_SOURCES =	m_wallops.c
m_who_la_SOURCES =	m_who.c
m_whois_la_SOURCES =	m_whois.c
m_whowas_la_SOURCES =	m_whowas.c
m_xline_la_SOURCES =	m_xline.c


m_accept_la_LIBADD = $(MODULE_LIBS)     
m_admin_la_LIBADD = $(MODULE_LIBS)     
m_adminwall_la_LIBADD = $(MODULE_LIBS)     
m_away_la_LIBADD = $(MODULE_LIBS)     
m_capab_la_LIBADD = $(MODULE_LIBS)     
m_cap_la_LIBADD = $(MODULE_LIBS)     
m_close_la_LIBADD = $(MODULE_LIBS)     
m_cmessage_la_LIBADD = $(MODULE_LIBS)     
m_connect_la_LIBADD = $(MODULE_LIBS)     
m_dline_la_LIBADD = $(MODULE_LIBS)     
m_encap_la_LIBADD = $(MODULE_LIBS)     
m_gline_la_LIBADD = $(MODULE_LIBS)     
m_gungline_la_LIBADD = $(MODULE_LIBS)     
m_help_la_LIBADD = $(MODULE_LIBS)     
m_info_la_LIBADD = $(MODULE_LIBS)     
m_invite_la_LIBADD = $(MODULE_LIBS)     
m_ison_la_LIBADD = $(MODULE_LIBS)     
m_kline_la_LIBADD = $(MODULE_LIBS)     
m_knock_la_LIBADD = $(MODULE_LIBS)     
m_links_la_LIBADD = $(MODULE_LIBS)     
m_list_la_LIBADD = $(MODULE_LIBS)     
m_locops_la_LIBADD = $(MODULE_LIBS)     
m_lusers_la_LIBADD = $(MODULE_LIBS)     
m_map_la_LIBADD = $(MODULE_LIBS)     
m_monitor_la_LIBADD = $(MODULE_LIBS)     
m_motd_la_LIBADD = $(MODULE_LIBS)     
m_names_la_LIBADD = $(MODULE_LIBS)     
m_oper_la_LIBADD = $(MODULE_LIBS)     
m_operspy_la_LIBADD = $(MODULE_LIBS)     
m_pass_la_LIBADD = $(MODULE_LIBS)     
m_ping_la_LIBADD = $(MODULE_LIBS)     
m_pong_la_LIBADD = $(MODULE_LIBS)     
m_post_la_LIBADD = $(MODULE_LIBS)     
m_rehash_la_LIBADD = $(MODULE_LIBS)     
m_restart_la_LIBADD = $(MODULE_LIBS)     
m_resv_la_LIBADD = $(MODULE_LIBS)     
m_set_la_LIBADD = $(MODULE_LIBS)     
m_stats_la_LIBADD = $(MODULE_LIBS)     
m_svinfo_la_LIBADD = $(MODULE_LIBS)     
m_tb_la_LIBADD = $(MODULE_LIBS)     
m_testline_la_LIBADD = $(MODULE_LIBS)     
m_testmask_la_LIBADD = $(MODULE_LIBS)     
m_time_la_LIBADD = $(MODULE_LIBS)     
m_topic_la_LIBADD = $(MODULE_LIBS)     
m_trace_la_LIBADD = $(MODULE_LIBS)     
m_unreject_la_LIBADD = $(MODULE_LIBS)     
m_user_la_LIBADD = $(MODULE_LIBS)     
m_userhost_la_LIBADD = $(MODULE_LIBS)     
m_version_la_LIBADD = $(MODULE_LIBS)     
m_wallops_la_LIBADD = $(MODULE_LIBS)     
m_who_la_LIBADD = $(MODULE_LIBS)     
m_whois_la_LIBADD = $(MODULE_LIBS)     
m_whowas_la_LIBADD = $(MODULE_LIBS)     
m_xline_la_LIBADD = $(MODULE_LIBS)     


core_m_die_la_LDFLAGS = -module $(MODULE_FLAGS) 
core_m_error_la_LDFLAGS = -module $(MODULE_FLAGS) 
core_m_join_la_LDFLAGS = -module $(MODULE_FLAGS) 
core_m_kick_la_LDFLAGS = -module $(MODULE_FLAGS) 
core_m_kill_la_LDFLAGS = -module $(MODULE_FLAGS) 
core_m_message_la_LDFLAGS = -module $(MODULE_FLAGS) 
core_m_mode_la_LDFLAGS = -module $(MODULE_FLAGS) 
core_m_nick_la_LDFLAGS = -module $(MODULE_FLAGS) 
core_m_part_la_LDFLAGS = -module $(MODULE_FLAGS) 
core_m_quit_la_LDFLAGS = -module $(MODULE_FLAGS) 
core_m_server_la_LDFLAGS = -module $(MODULE_FLAGS) 
core_m_squit_la_LDFLAGS = -module $(MODULE_FLAGS) 

core_m_die_la_SOURCES =	core/m_die.c
core_m_error_la_SOURCES =	core/m_error.c
core_m_join_la_SOURCES =	core/m_join.c
core_m_kick_la_SOURCES =	core/m_kick.c
core_m_kill_la_SOURCES =	core/m_kill.c
core_m_message_la_SOURCES =	core/m_message.c
core_m_mode_la_SOURCES =	core/m_mode.c
core_m_nick_la_SOURCES =	core/m_nick.c
core_m_part_la_SOURCES =	core/m_part.c
core_m_quit_la_SOURCES =	core/m_quit.c
core_m_server_la_SOURCES =	core/m_server.c
core_m_squit_la_SOURCES =	core/m_squit.c


modules_LTLIBRARIES =   \
m_accept.la	\
m_admin.la	\
m_adminwall.la	\
m_away.la	\
m_capab.la	\
m_cap.la	\
m_close.la	\
m_cmessage.la	\
m_connect.la	\
m_dline.la	\
m_encap.la	\
m_gline.la	\
m_gungline.la	\
m_help.la	\
m_info.la	\
m_invite.la	\
m_ison.la	\
m_kline.la	\
m_knock.la	\
m_links.la	\
m_list.la	\
m_locops.la	\
m_lusers.la	\
m_map.la	\
m_monitor.la	\
m_motd.la	\
m_names.la	\
m_oper.la	\
m_operspy.la	\
m_pass.la	\
m_ping.la	\
m_pong.la	\
m_post.la	\
m_rehash.la	\
m_restart.la	\
m_resv.la	\
m_set.la	\
m_stats.la	\
m_svinfo.la	\
m_tb.la		\
m_testline.la	\
m_testmask.la	\
m_time.la	\
m_topic.la	\
m_trace.la	\
m_unreject.la	\
m_user.la	\
m_userhost.la	\
m_version.la	\
m_wallops.la	\
m_who.la	\
m_whois.la	\
m_whowas.la	\
m_xline.la	

core_LTLIBRARIES = \
core/m_die.la	\
core/m_error.la	\
core/m_join.la	\
core/m_kick.la	\
core/m_kill.la	\
core/m_message.la	\
core/m_mode.la	\
core/m_nick.la	\
core/m_part.la	\
core/m_quit.la	\
core/m_server.la \
core/m_squit.la	


core_m_die_la_LIBADD = $(MODULE_LIBS)   
core_m_error_la_LIBADD = $(MODULE_LIBS)   
core_m_join_la_LIBADD = $(MODULE_LIBS)   
core_m_kick_la_LIBADD = $(MODULE_LIBS)   
core_m_kill_la_LIBADD = $(MODULE_LIBS)   
core_m_message_la_LIBADD = $(MODULE_LIBS)   
core_m_mode_la_LIBADD = $(MODULE_LIBS)   
core_m_nick_la_LIBADD = $(MODULE_LIBS)   
core_m_part_la_LIBADD = $(MODULE_LIBS) 
core_m_quit_la_LIBADD = $(MODULE_LIBS)  
core_m_server_la_LIBADD = $(MODULE_LIBS)
core_m_squit_la_LIBADD = $(MODULE_LIBS) 

if ENABLE_SERVICES
m_services_la_LDFLAGS = -module $(MODULE_FLAGS)  
m_services_la_SOURCES =	m_services.c
m_services_la_LIBADD = $(MODULE_LIBS)     
services_LTLIBRARIES = m_services.la
endif


modules: $(modules_LTLIBRARIES) $(services_LTLIBRARIES)
modules_core: $(core_LTLIBRARIES)

install-modulesLTLIBRARIES: $(modules_LTLIBRARIES) $(services_LTLIBRARIES)
	-@$(MKDIR_P) $(DESTDIR)$(modulesdir); \
	for x in $(modules_LTLIBRARIES) $(services_LTLIBRARIES); do $(SHELL) ../install-mod.sh $$x $(DESTDIR)$(modulesdir);done

install-coreLTLIBRARIES: $(core_LTLIBRARIES)
	-@$(MKDIR_P) $(DESTDIR)$(coredir); \
	for x in $(core_LTLIBRARIES); do $(SHELL) ../install-mod.sh $$x $(DESTDIR)$(coredir);done

if !DISABLE_BACKUPS
install-exec-hook: move-old-modules
endif

move-old-modules:
# move the old module directory out of the way, stale modules cause massive
# amounts of problems.
	-@if test -d $(DESTDIR)$(moduledir)-old; then \
		$(RB_RM) -rf $(DESTDIR)$(moduledir)-old; \
	fi
	-@if test -d $(DESTDIR)$(moduledir); then \
		echo "ircd: backing up modules"; \
		$(MV) $(DESTDIR)$(moduledir) $(DESTDIR)$(moduledir)-old; \
		$(MKDIR_P) $(DESTDIR)$(moduledir); \
	fi


else # !STATIC_MODULES

MSRCS =   \
m_accept.c	\
m_admin.c	\
m_adminwall.c	\
m_away.c	\
m_capab.c	\
m_cap.c	\
m_close.c	\
m_cmessage.c	\
m_connect.c	\
m_dline.c	\
m_encap.c	\
m_gline.c	\
m_gungline.c	\
m_help.c	\
m_info.c	\
m_invite.c	\
m_ison.c	\
m_kline.c	\
m_knock.c	\
m_links.c	\
m_list.c	\
m_locops.c	\
m_lusers.c	\
m_map.c	\
m_monitor.c	\
m_motd.c	\
m_names.c	\
m_oper.c	\
m_operspy.c	\
m_pass.c	\
m_ping.c	\
m_pong.c	\
m_post.c	\
m_rehash.c	\
m_restart.c	\
m_resv.c	\
m_set.c	\
m_stats.c	\
m_svinfo.c	\
m_tb.c		\
m_testline.c	\
m_testmask.c	\
m_time.c	\
m_topic.c	\
m_trace.c	\
m_unreject.c	\
m_user.c	\
m_userhost.c	\
m_version.c	\
m_wallops.c	\
m_who.c	\
m_whois.c	\
m_whowas.c	\
m_xline.c	

CORE_SRCS = \
core/m_die.c	\
core/m_error.c	\
core/m_join.c	\
core/m_kick.c	\
core/m_kill.c	\
core/m_message.c	\
core/m_mode.c	\
core/m_nick.c	\
core/m_part.c	\
core/m_quit.c	\
core/m_server.c \
core/m_squit.c	

if ENABLE_SERVICES
SERVICES_SRCS = m_services.c
endif

BUILT_SOURCE = static_modules.c
static_modules.c: static_modules.c.SH
	$(SHELL) static_modules.c.SH $(MSRCS) $(CORE_SRCS) $(SERVICES_SRCS)

libmodules_la_SOURCES = $(MSRCS) $(CORE_SRCS) $(SERVICES_SRCS)
libmodules_LTLIBRARIES = libmodules.la

all: static_modules.o libmodules.la

endif #STATIC_MODULES
