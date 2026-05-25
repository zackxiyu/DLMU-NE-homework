/**
 * @author      zackxiyu
 * @date        2026-05-18
 * 
 * @description
 * 计算机网络实验课大作业
 *   实验要求：
 *    1.实现数据包的捕获、分析，并保存捕获的数据包（完成）
 *    2.对捕获的信息进行统计分析（完成）（物理层，数据链路层，网络层，传输层，应用层）
 *    3.改写数据包内容并发送（完成）（具体为原始，反射，广播）
 *    4.进行实时流量监测等（完成）（在捕获时以列表形式显示）
 *    5.图形化界面（完成）（使用GTK，以AI为主进行实现）
 * 头文件在np.h里
 * 网络协议头结构体在protocol.h里（大部分来源于网上）（来源已给出）
 * 本作为wireshark的低配劣化版
 */
#include "np.h"
#include "protocol.h"
#define MAX_DEV_SIZE 100
#define MAX_PAC_SIZE 10000

static GtkWidget *g_output=NULL;
static GtkListStore *g_list=NULL;
static GtkWidget *packet_tree=NULL;
static pcap_t *g_adhandle=NULL;
static pcap_if_t *g_aimdev=NULL;
static pcap_if_t *g_devptr[MAX_DEV_SIZE+5]={};
static int g_endid=0;
static int packet_cnt=0;
static volatile int keep_running=1;
static pthread_t capture_tid;
typedef struct{
  int num;
  struct pcap_pkthdr header;
  u_char *data;
  char src_addr[64];
  char dst_addr[64];
  char protocol[32];
  char info[256];
}PacketData;

void append_text(const char *format,...);
gboolean add_packet_row(gpointer data);
void* capture_thread_func(void *arg);
void on_start_clicked(GtkButton *btn,gpointer data);
void on_stop_clicked(GtkButton *btn,gpointer data);
void on_send_clicked(GtkButton *btn,gpointer data);
void on_clear_clicked(GtkButton *btn,gpointer data);
void on_row_activated(GtkTreeView *tree_view, GtkTreePath *path, GtkTreeViewColumn *col, gpointer user_data);
void ana_physical_layer(const struct pcap_pkthdr *header,const u_char *pkth_data,const pcap_if_t *dev,int showdetails,int paclen);
void ana_datalink_layer(const u_char *pkth_data,int showdetails,int paclen);
void ana_network_layer(const u_char *pkth_data,int showdetails,int paclen);
void ana_transport_layer(const u_char *pkth_data,int showdetails,int paclen);
void ana_application_layer(const u_char *pkth_data,int showdetails,int paclen);
int analyse(const struct pcap_pkthdr *header,const u_char *pkth_data,const pcap_if_t *dev);
void ana_display(PacketData *pkt,const u_char *data,int len);
int set_filter(pcap_t *adhandle,GtkWidget *parent);

/**
 * append_text：代替printf，在图形化界面上输出
 * add_packet_row：流量监测
 * capture_thread_func：分线程抓包
 * on_系列函数：调用用户点击后的各项功能
 * ana_系列函数：分析各层的信息
 * analyse：调用ana_系列函数
 * ana_display：流量信息的复杂数据
 * set_filter：设置过滤器
 */

int main(int argc, char *argv[]){
  pcap_if_t *alldev=NULL;
  pcap_if_t *d=NULL;
  char errbuf[PCAP_ERRBUF_SIZE+5]={};

  gtk_init(&argc,&argv);
  
  GtkWidget *window=gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(window),"The Wirezack Network Analyzer");
  gtk_window_set_default_size(GTK_WINDOW(window),900,600);
  g_signal_connect(window,"destroy",G_CALLBACK(gtk_main_quit),NULL);
  
  GtkWidget *vbox=gtk_box_new(GTK_ORIENTATION_VERTICAL,5);
  gtk_container_add(GTK_CONTAINER(window),vbox);
  
  GtkWidget *toolbar=gtk_box_new(GTK_ORIENTATION_HORIZONTAL,5);
  gtk_box_pack_start(GTK_BOX(vbox),toolbar,FALSE,FALSE,5);
  
  GtkWidget *combo=gtk_combo_box_text_new();
  gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo),"Select a network interface:");
  gtk_combo_box_set_active(GTK_COMBO_BOX(combo),0);
  gtk_box_pack_start(GTK_BOX(toolbar),combo,FALSE,FALSE,5);
  
  GtkWidget *start_btn=gtk_button_new_with_label("Start");
  g_signal_connect(start_btn,"clicked",G_CALLBACK(on_start_clicked),combo);
  gtk_box_pack_start(GTK_BOX(toolbar),start_btn,FALSE,FALSE,5);

  GtkWidget *stop_btn=gtk_button_new_with_label("Stop");
  g_signal_connect(stop_btn,"clicked",G_CALLBACK(on_stop_clicked),NULL);
  gtk_box_pack_start(GTK_BOX(toolbar),stop_btn,FALSE,FALSE,5);

  GtkWidget *send_btn=gtk_button_new_with_label("Send");
  g_signal_connect(send_btn,"clicked",G_CALLBACK(on_send_clicked),combo);
  gtk_box_pack_start(GTK_BOX(toolbar),send_btn,FALSE,FALSE,5);

  GtkWidget *clear_btn=gtk_button_new_with_label("Clear");
  g_signal_connect(clear_btn,"clicked",G_CALLBACK(on_clear_clicked),NULL);
  gtk_box_pack_start(GTK_BOX(toolbar),clear_btn,FALSE,FALSE,5);
  
  GtkWidget *paned=gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
  gtk_box_pack_start(GTK_BOX(vbox),paned,TRUE,TRUE,5);
  
  GtkWidget *left_scroll=gtk_scrolled_window_new(NULL,NULL);
  gtk_paned_pack1(GTK_PANED(paned),left_scroll,TRUE,FALSE);
  
  g_list=gtk_list_store_new(7,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING
    ,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_POINTER);
  packet_tree=gtk_tree_view_new_with_model(GTK_TREE_MODEL(g_list));
  g_signal_connect(packet_tree,"row-activated",G_CALLBACK(on_row_activated),NULL);
  gtk_container_add(GTK_CONTAINER(left_scroll),packet_tree);
  
  GtkCellRenderer *rend=gtk_cell_renderer_text_new();
  GtkTreeViewColumn *col=NULL;
  col=gtk_tree_view_column_new_with_attributes("No.",rend,"text",0,NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(packet_tree),col);
  col=gtk_tree_view_column_new_with_attributes("Time",rend,"text",1,NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(packet_tree),col);
  col=gtk_tree_view_column_new_with_attributes("Source",rend,"text",2,NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(packet_tree),col);
  col=gtk_tree_view_column_new_with_attributes("Destination",rend,"text",3,NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(packet_tree),col);
  col=gtk_tree_view_column_new_with_attributes("Protocol",rend,"text",4,NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(packet_tree),col);
  col=gtk_tree_view_column_new_with_attributes("Length",rend,"text",5,NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(packet_tree),col);
  
  GtkWidget *right_scroll=gtk_scrolled_window_new(NULL,NULL);
  gtk_paned_pack2(GTK_PANED(paned),right_scroll,TRUE,FALSE);
  g_output=gtk_text_view_new();
  gtk_text_view_set_editable(GTK_TEXT_VIEW(g_output),FALSE);
  gtk_container_add(GTK_CONTAINER(right_scroll),g_output);
  
  if(pcap_findalldevs(&alldev,errbuf)==-1){
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo),"No device found");
  }
  else{
    g_endid=0;
    for(d=alldev;d;d=d->next){
      g_devptr[g_endid]=d;
      if(d->description)
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo),d->description);
      else
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo),d->name);
      g_endid++;
    }
  }

  gtk_widget_show_all(window);
  gtk_main();

  if(g_adhandle) pcap_close(g_adhandle);

  return 0;

}

/**
 * main
 * 此函数用于形成图形化界面
 * 具体逻辑都在各项点击后的功能实现中
 */

void print_hex_dump(const u_char *data,int len,int start,int end){
  GtkTextBuffer *buffer=gtk_text_view_get_buffer(GTK_TEXT_VIEW(g_output));
  GtkTextIter iter;
  gtk_text_buffer_get_end_iter(buffer,&iter);
  int base_offset=gtk_text_iter_get_offset(&iter);
  
  static GtkTextTag *tag=NULL;
  if(!tag){
    tag=gtk_text_buffer_create_tag(buffer,"high",
      "background","yellow",
      "foreground","black",
      NULL);
  }
  
  GString *str=g_string_new(NULL);
  GList *list=NULL;
  
  for(int i=0;i<len;i++){
    if(i%16==0){
      if(i>0) g_string_append(str,"\n");
      char tmp[32];
      sprintf(tmp,"0x%04X  ",i);
      g_string_append(str,tmp);
    }
    
    char tmp[8];
    sprintf(tmp,"%02X ",data[i]);
    int pos1=str->len;
    g_string_append(str,tmp);
    int pos2=str->len;
    
    if(i>=start&&i<end){
      list=g_list_append(list,GINT_TO_POINTER(base_offset+pos1));
      list=g_list_append(list,GINT_TO_POINTER(base_offset+pos2));
    }
  }
  g_string_append(str,"\n");
  
  gtk_text_buffer_insert(buffer,&iter,str->str,-1);
  gtk_text_buffer_get_end_iter(buffer,&iter);
  
  GList *p=list;
  while(p){
    int s=GPOINTER_TO_INT(p->data);
    p=p->next;
    int e=GPOINTER_TO_INT(p->data);
    p=p->next;
    GtkTextIter si,ei;
    gtk_text_buffer_get_iter_at_offset(buffer,&si,s);
    gtk_text_buffer_get_iter_at_offset(buffer,&ei,e);
    gtk_text_buffer_apply_tag(buffer,tag,&si,&ei);
  }
  
  g_list_free(list);
  g_string_free(str,TRUE);
}

/**
 * print_hex_dump
 * 此函数用以格式化打印16进制原始数据报，支持高亮一定的范围的文本
 * 每16字节换行，左边打印偏移地址，右边一字节为一组打印原始数据报，空格隔开
 *    gtk_text_view_函数从缓冲区中获取信息，具体信息可以从其名称中得知
 *    tag设置高亮类型
 *    pos设置偏移起始位置
 *    insert一次性插入
 *    while循环中应用高亮
 *    最后释放内存
 */

void append_text(const char *format,...){
  if(!g_output) return;
  va_list args;
  va_start(args,format);
  va_list args_copy;
  va_copy(args_copy,args);
  int len=vsnprintf(NULL,0,format,args_copy);
  va_end(args_copy);
  char *text=(char *)malloc(len+1);
  if(text){
    vsnprintf(text,len+1,format,args);
    va_end(args);
    GtkTextBuffer *buffer=gtk_text_view_get_buffer(GTK_TEXT_VIEW(g_output));
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buffer,&end);
    gtk_text_buffer_insert(buffer,&end,text,-1);
    free(text);
  }
  else{
    va_end(args);
  }
}

/**
 * append_text
 * 此函数用以将内容输出到窗口中，代替了原来所有的printf
 *    va_函数为可变参数函数，用以将format内容进行操作
 *    vsnprintf为安全的可变参数的sprintf
 *    接下去获取缓冲区，获取尾迭代器，插入信息
 */

gboolean add_packet_row(gpointer data){
  PacketData *pkt=(PacketData*)data;
  if(!g_list) return FALSE;
  GtkTreeIter iter;
  char num_str[16],time_str[32],len_str[16];
  char time_with_us[48];
  time_t tv_sec=pkt->header.ts.tv_sec;
  struct tm *ltime=localtime(&tv_sec);
  strftime(time_str,sizeof(time_str),"%H:%M:%S",ltime);
  snprintf(time_with_us,sizeof(time_with_us),"%s.%06d",time_str,(int)(pkt->header.ts.tv_usec));
  sprintf(num_str,"%d",pkt->num);
  sprintf(len_str,"%d",pkt->header.len);
  gtk_list_store_append(g_list,&iter);
  gtk_list_store_set(g_list,&iter,
    0,num_str,
    1,time_with_us,
    2,pkt->src_addr,
    3,pkt->dst_addr,
    4,pkt->protocol,
    5,len_str,
    6,pkt,
    -1);
  return FALSE;
}

/**
 * add_packet_row
 * 此函数用以在窗口上简略打印数据报信息
 *    s_函数将数据放到对应缓冲区，是GTK需要的输出方式
 *    gtk_list_store_函数可以放入不定数量的参数，可以打印多行到窗口上
 */

void* capture_thread_func(void *arg){
  struct pcap_pkthdr *header=NULL;
  const u_char *pkt_data=NULL;
  int res=0;
  while(keep_running){
    res=pcap_next_ex(g_adhandle,&header,&pkt_data);
    if(res==1){
      packet_cnt++;
      PacketData *pkt=malloc(sizeof(PacketData));
      pkt->num=packet_cnt;
      pkt->header=*header;
      pkt->data=malloc(header->len);
      memcpy(pkt->data,pkt_data,header->len);
      ana_display(pkt,pkt_data,header->len);
      gdk_threads_add_idle((GSourceFunc)add_packet_row,pkt);
    }
  }
  return NULL;
}

/**
 * capture_thread_func
 * 这个函数用以独立线程抓包
 *    对于成功抓取的包，复制其信息并交给主线程让GTK显示
 */

void on_start_clicked(GtkButton *btn,gpointer data){
  GtkWidget *combo=GTK_WIDGET(data);
  int id=gtk_combo_box_get_active(GTK_COMBO_BOX(combo));
  char errbuf[PCAP_ERRBUF_SIZE+5]={};
  if(id<=0){
    append_text("Please select a network interface\n");
    return;
  }
  id--;
  if(id>=g_endid){
    append_text("Invalid interface\n");
    return;
  }
  g_adhandle=pcap_open_live(g_devptr[id]->name,65536,1,1000,errbuf);
  if(g_adhandle==NULL){
    append_text("Failed to open adapter: %s\n",errbuf);
    return;
  }
  if(set_filter(g_adhandle,GTK_WIDGET(gtk_widget_get_toplevel(GTK_WIDGET(btn))))!=0){
    pcap_close(g_adhandle);
    g_adhandle=NULL;
    return;
  }
  g_aimdev=g_devptr[id];
  gtk_list_store_clear(g_list);
  packet_cnt=0;
  keep_running=1;
  pthread_create(&capture_tid,NULL,capture_thread_func,NULL);
  append_text("\n++++++++++Start capturing++++++++++\n");
}

/**
 * on_start_clicked
 * 此函数用以执行用户点击start之后的操作
 *    前两行用于展开选项卡并获取用户选中的网卡
 *    在获取网卡后创建一个线程并调用抓包函数
 */

void on_stop_clicked(GtkButton *btn,gpointer data){
  keep_running=0;
  if(g_adhandle){
    pcap_breakloop(g_adhandle);
    pthread_join(capture_tid,NULL);
    pcap_close(g_adhandle);
    g_adhandle=NULL;
    append_text("\n++++++++++Stop capturing++++++++++\n");
  }
}

/**
 * on_stop_clicked
 * 此函数用以在用户点击stop后结束抓包
 *    此函数内所有语句都用于停止抓包即重置状态以准备下一次抓包
 */

void on_send_clicked(GtkButton *btn,gpointer data){
  GtkWidget *combo=GTK_WIDGET(data);
  GtkTreeSelection *sel=gtk_tree_view_get_selection(GTK_TREE_VIEW(packet_tree));
  GtkTreeIter iter;
  GtkTreeModel *model;
  char errbuf[PCAP_ERRBUF_SIZE+5]={};
  if(!gtk_tree_selection_get_selected(sel,&model,&iter)){
    append_text("No packet selected!\n");
    return;
  }
  PacketData *pkt;
  gtk_tree_model_get(model,&iter,6,&pkt,-1);
  if(!pkt||!pkt->data){
    append_text("Invalid packet data!\n");
    return;
  }
  int idx=gtk_combo_box_get_active(GTK_COMBO_BOX(combo));
  if(idx<=0){
    append_text("Please select a network interface!\n");
    return;
  }
  idx--;
  if(idx>=g_endid){
    append_text("Invalid interface!\n");
    return;
  }
  GtkWidget *dialog=gtk_message_dialog_new(NULL,GTK_DIALOG_MODAL,GTK_MESSAGE_QUESTION,
    GTK_BUTTONS_NONE,"Select send mode");
  gtk_dialog_add_buttons(GTK_DIALOG(dialog),
    "Raw",1,
    "Echo",2,
    "Broadcast",3,
    NULL);
  gint result=gtk_dialog_run(GTK_DIALOG(dialog));
  gtk_widget_destroy(dialog);
  if(result<1){
    append_text("Send cancelled\n");
    return;
  }
  u_char *send_data=malloc(pkt->header.len);
  memcpy(send_data,pkt->data,pkt->header.len);
  eth_hdr *eth=(eth_hdr*)send_data;
  if(result==2){
    unsigned char tmp[6];
    memcpy(tmp,eth->srcmac,6);
    memcpy(eth->srcmac,eth->dstmac,6);
    memcpy(eth->dstmac,tmp,6);
    append_text("\nEcho mode:\n");
  }
  else if(result==3){
    memset(eth->dstmac,0xFF,6);
    append_text("\nBroadcast mode:\n");
  }
  else{
    append_text("\nRaw mode:\n");
  }
  pcap_t *send_handle=pcap_open_live(g_devptr[idx]->name,65536,0,1000,errbuf);
  if(send_handle==NULL){
    append_text("Failed to open adapter: %s\n",errbuf);
    free(send_data);
    return;
  }
  append_text("Sending...\n");
  int send_result=pcap_sendpacket(send_handle,send_data,pkt->header.len);
  if(send_result==0){
    append_text("Sent %d bytes\n",pkt->header.len);
  }
  else{
    append_text("Send failed\n");
  }
}

/**
 * on_send_clicked
 * 此函数用以修改并发送数据报
 * 共三个模式：Raw，Echo，Broadcast
 * 分别是发送原数据报，交换mac地址并发送，全1目的地址的广播发送
 *     它会先获取用户选中的包，
 *     再获取选中的网卡，
 *     然后让用户选择对应的发送模式，
 *     最后对包做相应的操作并发送
 */

void on_clear_clicked(GtkButton *btn,gpointer data){
  if(!g_output) return;
  GtkTextBuffer *buffer=gtk_text_view_get_buffer(GTK_TEXT_VIEW(g_output));
  gtk_text_buffer_set_text(buffer,"",-1);
}

/**
 * on_clear_clicked
 * 此函数用于清除用户点击按键后产生的信息
 *    获取缓冲区并清空
 */

void on_row_activated(GtkTreeView *tree_view,GtkTreePath *path,GtkTreeViewColumn *col,gpointer user_data){
  GtkTreeIter iter;
  GtkTreeModel *model=gtk_tree_view_get_model(tree_view);
  if(gtk_tree_model_get_iter(model,&iter,path)){
    PacketData *pkt;
    gtk_tree_model_get(model,&iter,6,&pkt,-1);
    if(pkt&&pkt->data){
      GtkWidget *dialog=gtk_message_dialog_new(NULL,GTK_DIALOG_MODAL,GTK_MESSAGE_QUESTION,
        GTK_BUTTONS_NONE,"Select layer to highlight");
      gtk_dialog_add_buttons(GTK_DIALOG(dialog),
        "None",0,
        "Physical",1,
        "Datalink",2,
        "Network",3,
        "Transport",4,
        "Application",5,
        NULL);
      gint result=gtk_dialog_run(GTK_DIALOG(dialog));
      gtk_widget_destroy(dialog);
      
      append_text("\n----------------------------------------\n");
      append_text("No. %d\n",pkt->num);
      append_text("----------------------------------------\n");
      
      if(result==0){
        analyse(&pkt->header,pkt->data,g_aimdev);
      }
      else{
        int paclen=pkt->header.len;
        switch(result){
          case 1:
            ana_physical_layer(&pkt->header,pkt->data,g_aimdev,1,paclen);
            break;
          case 2:
            ana_datalink_layer(pkt->data,1,paclen);
            break;
          case 3:
            ana_network_layer(pkt->data,1,paclen);
            break;
          case 4:
            ana_transport_layer(pkt->data,1,paclen);
            break;
          case 5:
            ana_application_layer(pkt->data,1,paclen);
            break;
        }
      }
    }
  }
}

/**
 * on_row_activated
 * 此函数用于调用打印数据报函数
 *    先将视图转换为模型，
 *    获取迭代器，
 *    数据包非空则弹出协议层分析选项，
 *    调用分析函数对对应层分析
 */

void ana_physical_layer(const struct pcap_pkthdr *header,const u_char *pkth_data,const pcap_if_t *dev,int showdetails,int paclen){
  append_text("1.Pysical Layer: ");
  append_text("Packet,");
  append_text("%d bytes on wire (%d bits),",header->len,header->len*8);
  append_text("%d bytes captured (%d bits) ",header->caplen,header->caplen*8);
  if(!showdetails){
    append_text("\n");
    return;
  }
  append_text("on %s\n",dev->name);
  print_hex_dump(pkth_data,paclen,0,paclen);
}

/**
 * ana_physical_layer
 * 此函数用以分析物理层
 *    简化内容包含：实际长度，抓取长度
 *    细节内容包含：网卡名称，原始数据报的物理层高亮
 */

void ana_datalink_layer(const u_char *pkth_data,int showdetails,int paclen){
  eth_hdr *eth=(eth_hdr*)pkth_data;
  unsigned short eth_type=ntohs(eth->eth_type);
  int eth_len=sizeof(eth_hdr);
  append_text("2.Datalink Layer: ");
  append_text("0x%04X, ",eth_type);
  append_text("Src=%02X:%02X:%02X:%02X:%02X:%02X, ",
    eth->srcmac[0],eth->srcmac[1],eth->srcmac[2],
    eth->srcmac[3],eth->srcmac[4],eth->srcmac[5]);
  append_text("Dst=%02X:%02X:%02X:%02X:%02X:%02X\n",
    eth->dstmac[0],eth->dstmac[1],eth->dstmac[2],
    eth->dstmac[3],eth->dstmac[4],eth->dstmac[5]);
  if(showdetails){
    print_hex_dump(pkth_data,paclen,0,eth_len);
  }
}

/**
 * ana_datalink_layer
 * 此函数用以分析数据链路层
 *    简化内容包含：协议类型（ipv4，ipv6），源地址，目的地址
 *    细节内容包含：原始数据报的数据链路层高亮
 */

void ana_network_layer(const u_char *pkth_data,int showdetails,int paclen){
  eth_hdr *eth=(eth_hdr*)pkth_data;
  unsigned short eth_type=ntohs(eth->eth_type);
  char ip_str[46];
  int offset=0;
  int len=0;
  append_text("3.Network Layer: ");
  
  if(eth_type==ETH_TYPE_IP){
    ip_hdr *ip=(ip_hdr*)(pkth_data+sizeof(eth_hdr));
    append_text("IPv4, ");
    append_text("Src=%s, ",inet_ntop(AF_INET,&(ip->srcaddr),ip_str,sizeof(ip_str)));
    append_text("Dst=%s\n",inet_ntop(AF_INET,&(ip->dstaddr),ip_str,sizeof(ip_str)));
    if(showdetails){
      offset=sizeof(eth_hdr);
      len=ip->ihl*4;
      print_hex_dump(pkth_data,paclen,offset,offset+len);
    }
  }
  else if(eth_type==ETH_TYPE_IPV6){
    ipv6_hdr *ipv6=(ipv6_hdr*)(pkth_data+sizeof(eth_hdr));
    append_text("IPv6 ");
    append_text("Src=%s, ",inet_ntop(AF_INET6,&(ipv6->srcaddr),ip_str,sizeof(ip_str)));
    append_text("Dst=%s\n",inet_ntop(AF_INET6,&(ipv6->dstaddr),ip_str,sizeof(ip_str)));
    if(showdetails){
      offset=sizeof(eth_hdr);
      len=sizeof(ipv6_hdr);
      print_hex_dump(pkth_data,paclen,offset,offset+len);
    }
  }
  else{
    append_text("Unknown (0x%04X)\n",eth_type);
  }
}

/**
 * ana_network_layer
 * 此函数用以分析网络层
 *    简化内容包含：协议类型（ipv4，ipv6），源地址，目的地址
 *    细节内容包含：原始数据报的网络层高亮
 */

void ana_transport_layer(const u_char *pkth_data,int showdetails,int paclen){
  eth_hdr *eth=(eth_hdr*)pkth_data;
  unsigned short eth_type=ntohs(eth->eth_type);
  int offset=0;
  int len=0;
  
  if(eth_type==ETH_TYPE_IPV6){
    ipv6_hdr *ipv6=(ipv6_hdr*)(pkth_data+sizeof(eth_hdr));
    const u_char *l4_data=pkth_data+sizeof(eth_hdr)+sizeof(ipv6_hdr);
    append_text("4.Transport Layer: ");
    if(ipv6->next_header==PROTO_TCP){
      tcp_hdr *tcp=(tcp_hdr*)l4_data;
      append_text("TCP, ");
      append_text("Src=%d, ",ntohs(tcp->src_port));
      append_text("Dst=%d\n",ntohs(tcp->dst_port));
      if(showdetails){
        offset=sizeof(eth_hdr)+sizeof(ipv6_hdr);
        len=tcp->thl*4;
        print_hex_dump(pkth_data,paclen,offset,offset+len);
      }
    }
    else if(ipv6->next_header==PROTO_UDP){
      udp_hdr *udp=(udp_hdr*)l4_data;
      append_text("UDP ");
      append_text("Src=%d, ",ntohs(udp->src_port));
      append_text("Dst=%d\n",ntohs(udp->dst_port));
      if(showdetails){
        offset=sizeof(eth_hdr)+sizeof(ipv6_hdr);
        len=sizeof(udp_hdr);
        print_hex_dump(pkth_data,paclen,offset,offset+len);
      }
    }
    else{
      append_text("Unknown\n");
    }
    return;
  }
  
  if(eth_type!=ETH_TYPE_IP) return;
  
  ip_hdr *ip=(ip_hdr*)(pkth_data+sizeof(eth_hdr));
  int ip_header_len=ip->ihl*4;
  const u_char *l4_data=pkth_data+sizeof(eth_hdr)+ip_header_len;
  append_text("4.Transport Layer: ");
  if(ip->protocol==PROTO_TCP){
    tcp_hdr *tcp=(tcp_hdr*)l4_data;
    append_text("TCP, ");
    append_text("Src=%d, ",ntohs(tcp->src_port));
    append_text("Dst=%d\n",ntohs(tcp->dst_port));
    if(showdetails){
      offset=sizeof(eth_hdr)+ip_header_len;
      len=tcp->thl*4;
      print_hex_dump(pkth_data,paclen,offset,offset+len);
    }
  }
  else if(ip->protocol==PROTO_UDP){
    udp_hdr *udp=(udp_hdr*)l4_data;
    append_text("UDP, ");
    append_text("Src=%d, ",ntohs(udp->src_port));
    append_text("Dst=%d\n",ntohs(udp->dst_port));
    if(showdetails){
      offset=sizeof(eth_hdr)+ip_header_len;
      len=sizeof(udp_hdr);
      print_hex_dump(pkth_data,paclen,offset,offset+len);
    }
  }
  else if(ip->protocol==PROTO_ICMP){
    icmp_hdr *icmp=(icmp_hdr*)l4_data;
    append_text("ICMP ");
    if(showdetails){
      offset=sizeof(eth_hdr)+ip_header_len;
      len=sizeof(icmp_hdr);
      print_hex_dump(pkth_data,paclen,offset,offset+len);
    }
    else{
      append_text("\n");
    }
  }
  else{
    append_text("Protocol=%d (Unknown)\n",ip->protocol);
  }
}

/**
 * ana_transport_layer
 * 此函数用以分析网络层
 *    简化内容包含：协议类型（tcp，udp，icmp），源地址，目的地址
 *    细节内容包含：原始数据报的传输层高亮
 */

void ana_application_layer(const u_char *pkth_data,int showdetails,int paclen){
  eth_hdr *eth=(eth_hdr*)pkth_data;
  unsigned short eth_type=ntohs(eth->eth_type);
  append_text("5.Application Layer: ");
  
  if(eth_type!=ETH_TYPE_IP&&eth_type!=ETH_TYPE_IPV6){
    append_text("Unknown\n");
    return;
  }
  
  const u_char *payload=NULL;
  int payload_len=0;
  int offset=0;
  
  if(eth_type==ETH_TYPE_IP){
    ip_hdr *ip=(ip_hdr*)(pkth_data+sizeof(eth_hdr));
    int ip_header_len=ip->ihl*4;
    const u_char *l4_data=pkth_data+sizeof(eth_hdr)+ip_header_len;
    
    if(ip->protocol==PROTO_TCP){
      tcp_hdr *tcp=(tcp_hdr*)l4_data;
      int tcp_header_len=tcp->thl*4;
      payload=l4_data+tcp_header_len;
      payload_len=ntohs(ip->tot_len)-ip_header_len-tcp_header_len;
      offset=sizeof(eth_hdr)+ip_header_len+tcp_header_len;
    }
    else if(ip->protocol==PROTO_UDP){
      udp_hdr *udp=(udp_hdr*)l4_data;
      payload=l4_data+sizeof(udp_hdr);
      payload_len=ntohs(udp->uhl)-sizeof(udp_hdr);
      offset=sizeof(eth_hdr)+ip_header_len+sizeof(udp_hdr);
    }
  }
  else if(eth_type==ETH_TYPE_IPV6){
    ipv6_hdr *ipv6=(ipv6_hdr*)(pkth_data+sizeof(eth_hdr));
    const u_char *l4_data=pkth_data+sizeof(eth_hdr)+sizeof(ipv6_hdr);
    
    if(ipv6->next_header==PROTO_TCP){
      tcp_hdr *tcp=(tcp_hdr*)l4_data;
      int tcp_header_len=tcp->thl*4;
      payload=l4_data+tcp_header_len;
      payload_len=ntohs(ipv6->payload_len)-tcp_header_len;
      offset=sizeof(eth_hdr)+sizeof(ipv6_hdr)+tcp_header_len;
    }
    else if(ipv6->next_header==PROTO_UDP){
      udp_hdr *udp=(udp_hdr*)l4_data;
      payload=l4_data+sizeof(udp_hdr);
      payload_len=ntohs(ipv6->payload_len)-sizeof(udp_hdr);
      offset=sizeof(eth_hdr)+sizeof(ipv6_hdr)+sizeof(udp_hdr);
    }
  }
  
  if(payload_len>0){
    append_text("%d bytes",payload_len);
    if(payload_len>=3){
      if(memcmp(payload,"GET",3)==0||memcmp(payload,"POST",4)==0){
        append_text(" [HTTP]");
      }
      else if(payload_len>=4&&memcmp(payload,"HTTP",4)==0){
        append_text(" [HTTP Response]");
      }
      else if(payload_len>=2&&payload[0]==0x16&&payload[1]==0x03){
        append_text(" [TLS]");
      }
      else if(payload_len>=2&&payload[0]==0x17&&payload[1]==0x03){
        append_text(" [TLS Encrypted Data]");
      }
    }
    append_text("\n");
    if(showdetails){
      print_hex_dump(pkth_data,paclen,offset,offset+payload_len);
    }
  }
  else{
    append_text("No application data\n");
  }
}

/**
 * ana_application_layer
 * 此函数用以分析网络层
 *    简化内容包含：协议类型（http，tls）
 *    细节内容包含：原始数据报的应用层高亮
 */

int analyse(const struct pcap_pkthdr *header,const u_char *pkth_data,const pcap_if_t *dev){
  int paclen=header->len;
  ana_physical_layer(header,pkth_data,dev,0,paclen);
  ana_datalink_layer(pkth_data,0,paclen);
  ana_network_layer(pkth_data,0,paclen);
  ana_transport_layer(pkth_data,0,paclen);
  ana_application_layer(pkth_data,0,paclen);
  print_hex_dump(pkth_data,paclen,0,0);
  return paclen;
}

/**
 * analyse
 * 此函数用于调用各个分析函数
 * 以及打印各层简略信息和非高亮原始数据报
 */

void ana_display(PacketData *pkt,const u_char *data,int len){
  strcpy(pkt->src_addr,"N/A");
  strcpy(pkt->dst_addr,"N/A");
  strcpy(pkt->protocol,"Unknown");
  strcpy(pkt->info,"");
  
  if(len<sizeof(eth_hdr)) return;
  
  eth_hdr *eth=(eth_hdr*)data;
  unsigned short eth_type=ntohs(eth->eth_type);
  
  if(eth_type==ETH_TYPE_IP){
    if(len<sizeof(eth_hdr)+sizeof(ip_hdr)) return;
    ip_hdr *ip=(ip_hdr*)(data+sizeof(eth_hdr));
    char src_ip[46],dst_ip[46];
    inet_ntop(AF_INET,&(ip->srcaddr),src_ip,sizeof(src_ip));
    inet_ntop(AF_INET,&(ip->dstaddr),dst_ip,sizeof(dst_ip));
    strcpy(pkt->src_addr,src_ip);
    strcpy(pkt->dst_addr,dst_ip);
    int ip_header_len=ip->ihl*4;
    if(ip->protocol==PROTO_TCP){
      if(len<sizeof(eth_hdr)+ip_header_len+sizeof(tcp_hdr)) return;
      tcp_hdr *tcp=(tcp_hdr*)(data+sizeof(eth_hdr)+ip_header_len);
      int src_port=ntohs(tcp->src_port);
      int dst_port=ntohs(tcp->dst_port);
      if(src_port==80||dst_port==80) strcpy(pkt->protocol,"HTTP");
      else if(src_port==443||dst_port==443) strcpy(pkt->protocol,"TLS");
      else if(src_port==53||dst_port==53) strcpy(pkt->protocol,"DNS");
      else strcpy(pkt->protocol,"TCP");
      char flags[16]="";
      if(tcp->flag&0x01) strcat(flags,"FIN,");
      if(tcp->flag&0x02) strcat(flags,"SYN,");
      if(tcp->flag&0x04) strcat(flags,"RST,");
      if(tcp->flag&0x10) strcat(flags,"ACK,");
      if(strlen(flags)>0) flags[strlen(flags)-1]='\0';
      else strcpy(flags,"None");
      snprintf(pkt->info,sizeof(pkt->info),"%d → %d [%s] Seq=%u Ack=%u Win=%d",
        src_port,dst_port,flags,ntohl(tcp->seq_no),ntohl(tcp->ack_no),ntohs(tcp->wnd_size));
    }
    else if(ip->protocol==PROTO_UDP){
      if(len<sizeof(eth_hdr)+ip_header_len+sizeof(udp_hdr)) return;
      udp_hdr *udp=(udp_hdr*)(data+sizeof(eth_hdr)+ip_header_len);
      int src_port=ntohs(udp->src_port);
      int dst_port=ntohs(udp->dst_port);
      if(src_port==53||dst_port==53) strcpy(pkt->protocol,"DNS");
      else if(src_port==67||dst_port==67) strcpy(pkt->protocol,"DHCP");
      else strcpy(pkt->protocol,"UDP");
      snprintf(pkt->info,sizeof(pkt->info),"%d → %d Len=%d",src_port,dst_port,ntohs(udp->uhl)-8);
    }
    else if(ip->protocol==PROTO_ICMP){
      strcpy(pkt->protocol,"ICMP");
      icmp_hdr *icmp=(icmp_hdr*)(data+sizeof(eth_hdr)+ip_header_len);
      snprintf(pkt->info,sizeof(pkt->info),"Type=%d Code=%d",icmp->icmp_type,icmp->code);
    }
  }
  else if(eth_type==ETH_TYPE_IPV6){
    if(len<sizeof(eth_hdr)+sizeof(ipv6_hdr)) return;
    ipv6_hdr *ipv6=(ipv6_hdr*)(data+sizeof(eth_hdr));
    char src_ip6[INET6_ADDRSTRLEN],dst_ip6[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6,&(ipv6->srcaddr),src_ip6,sizeof(src_ip6));
    inet_ntop(AF_INET6,&(ipv6->dstaddr),dst_ip6,sizeof(dst_ip6));
    strcpy(pkt->src_addr,src_ip6);
    strcpy(pkt->dst_addr,dst_ip6);
    if(ipv6->next_header==PROTO_TCP) strcpy(pkt->protocol,"TCPv6");
    else if(ipv6->next_header==PROTO_UDP) strcpy(pkt->protocol,"UDPv6");
    else strcpy(pkt->protocol,"IPv6");
    snprintf(pkt->info,sizeof(pkt->info),"Next Header: %d",ipv6->next_header);
  }
  else if(eth_type==ETH_TYPE_ARP){
    strcpy(pkt->protocol,"ARP");
    snprintf(pkt->info,sizeof(pkt->info),"ARP Request/Reply");
    snprintf(pkt->src_addr,sizeof(pkt->src_addr),"%02X:%02X:%02X:%02X:%02X:%02X",
      eth->srcmac[0],eth->srcmac[1],eth->srcmac[2],
      eth->srcmac[3],eth->srcmac[4],eth->srcmac[5]);
    snprintf(pkt->dst_addr,sizeof(pkt->dst_addr),"%02X:%02X:%02X:%02X:%02X:%02X",
      eth->dstmac[0],eth->dstmac[1],eth->dstmac[2],
      eth->dstmac[3],eth->dstmac[4],eth->dstmac[5]);
  }
}

/**
 * ana_display
 * 此函数用于打印流量分析的各协议信息
 *    以太网类型主要为ipv4，ipv6，arp
 *    各自又有各自的不同协议，简单地挑几个分析
 */

 int set_filter(pcap_t *adhandle, GtkWidget *parent){
  GtkWidget *dialog;
  GtkWidget *content_area;
  GtkWidget *label;
  GtkWidget *entry;
  GtkWidget *hbox;
  gint result;
  struct bpf_program fp;
  const char *filter_str;
  int ret=0;
  
  dialog=gtk_dialog_new_with_buttons("Set Capture Filter",
    GTK_WINDOW(parent),GTK_DIALOG_MODAL,
    "OK",GTK_RESPONSE_OK,
    "Skip",GTK_RESPONSE_CANCEL,
    NULL);
  gtk_window_set_default_size(GTK_WINDOW(dialog),400,100);
  content_area=gtk_dialog_get_content_area(GTK_DIALOG(dialog));
  hbox=gtk_box_new(GTK_ORIENTATION_HORIZONTAL,10);
  gtk_container_set_border_width(GTK_CONTAINER(hbox),10);
  label=gtk_label_new("Filter:");
  entry=gtk_entry_new();
  gtk_entry_set_placeholder_text(GTK_ENTRY(entry),
    "Set filter");
  gtk_entry_set_width_chars(GTK_ENTRY(entry),30);
  gtk_box_pack_start(GTK_BOX(hbox),label,FALSE,FALSE,5);
  gtk_box_pack_start(GTK_BOX(hbox),entry,TRUE,TRUE,5);
  gtk_container_add(GTK_CONTAINER(content_area),hbox);
  gtk_widget_show_all(dialog);
  result=gtk_dialog_run(GTK_DIALOG(dialog));
  
  if(result==GTK_RESPONSE_OK){
    filter_str=gtk_entry_get_text(GTK_ENTRY(entry));
    if(filter_str && strlen(filter_str)>0){
      append_text("Compiling filter: %s\n",filter_str);
      if(pcap_compile(adhandle,&fp,filter_str,1,0)==-1){
        append_text("Failed to compile filter: %s\n",pcap_geterr(adhandle));
        ret=-1;
      }
      else{
        if(pcap_setfilter(adhandle,&fp)==-1){
          append_text("Failed to set filter: %s\n",pcap_geterr(adhandle));
          ret=-1;
        }
        else{
          append_text("Filter applied: %s\n",filter_str);
        }
        pcap_freecode(&fp);
      }
    }
  }
  else{
    append_text("No filter, capturing all packets\n");
  }
  gtk_widget_destroy(dialog);
  return ret;
}

/**
 * set_filter
 * 此函数用以设置过滤器，注意需要使用pcap语法，和wireshark语法不一样
 * （wireshark：ip.addr==xxx.xxx.xxx.xxx，pacp：host xxx.xxx.xxx.xxx）
 * 这个函数只是把过滤器显示图形化了一下，主要功能依靠内置函数pcap_setfilter
 *    pcap_compile用以编译表达式
 *    pcap_setfilter设置到内核
 *    Skip抓所有包，即跳过设置
 */
