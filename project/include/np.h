#define _WIN32_WINNT 0x0600
#include<winsock2.h>
#include<windows.h>
#include<ws2tcpip.h>
#include<pcap.h>
//以上为抓包相关文件，主要为npcap+npcap_sdk

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<ctype.h>
#include<time.h>
#include<signal.h>
#include<unistd.h>
//以上为基础功能相关文件

#include<gtk/gtk.h>
#include<glib.h>
#include<pthread.h>
#include<stdarg.h>
//以上为图形化相关文件，主要为GTK