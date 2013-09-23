
#include "httpd.h"
#include "http_config.h"
#include "apr_buckets.h"
#include "apr_general.h"
#include "apr_lib.h"
#include "util_filter.h"
#include "http_request.h"
#include <apr_strings.h>
#include <apr_strmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include <ctype.h>

 const char *Filter_name= "Noncefilter";

 const char *replace_string="script nonce = "; // later random value will be concatenated to this

 const char *Find_string="script nonce = abcdcfvX9eW+rl03HEGw3sVMx23232324134sdf"; // find this string in the body of the request- hardcoded secret value

// Module Declaration
module AP_MODULE_DECLARE_DATA script_nonce_filter_module;

typedef struct
{
     int on;
}nonce_config;


// Helpful in creating per-server configuration and initialization of the structure
static void *scriptnonceFilterCreateServerConfig(apr_pool_t *p,server_rec *s)
{
    
    nonce_config *config=apr_pcalloc(p,sizeof *config);

    config->on=0;

    return config;
}

// Inserts the output Filter based on the condition
static void scriptnonceFilterInsertFilter(request_rec *r)
{
     nonce_config *config=ap_get_module_config(r->server->module_config,&script_nonce_filter_module);

     if(!config->on)
          return;

     ap_add_output_filter(Filter_name,NULL,r,r->connection); // adds the output filter to the output filter chain
}

// Our output filter which processes the data accordingly
static apr_status_t scriptnonceFilterOutFilter(ap_filter_t *f, apr_bucket_brigade *pbbIn)
{
    request_rec *r = f->r;
    conn_rec *c = r->connection;
    apr_bucket *pbktIn;
    apr_bucket_brigade *pbbOut;
    char *m_header;

    unsigned char* clear_text=NULL;

    unsigned char *nonce_value=NULL;

    unsigned char* Replace_string=NULL;

    clear_text=apr_bucket_alloc(20, c->bucket_alloc);

    nonce_value=apr_bucket_alloc(20+6, c->bucket_alloc);

    memset(clear_text,0,20);

    apr_generate_random_bytes(clear_text,20); // Creating Random string

    apr_sha1_base64(clear_text, strlen(clear_text), nonce_value);  // Giving the random string as a seed value to produce SHA1 random value

    nonce_value[strlen(clear_text)+6]='\0';

    Replace_string= apr_bucket_alloc(strlen(replace_string)+strlen(nonce_value), c->bucket_alloc);

    Replace_string = apr_pstrcat(r->pool,replace_string,nonce_value,NULL); // Final replace string that needs to replace the Find_string

     char *p0=NULL,*p1=NULL,*p2=NULL,*p3=NULL;

     int find_len;
     find_len=strlen(Find_string);
     int repl_len;
     repl_len=strlen(Replace_string);

     int dist=0,dist1=0;
     int diff;
     int diff1;

     diff=repl_len-find_len;

     if(diff<0)
     {
      diff1=find_len-repl_len;
     }
  
  // Adding CSP fields to the out going header
    m_header = apr_pstrcat(r->pool, "script-nonce ",nonce_value,";",NULL);

    apr_table_add(r->headers_out,"Content-Security-Policy",(const char*)m_header);

    pbbOut=apr_brigade_create(r->pool, c->bucket_alloc); // creating a new brigade which is passed down to the next filter
    
    for (pbktIn = APR_BRIGADE_FIRST(pbbIn);
         pbktIn != APR_BRIGADE_SENTINEL(pbbIn); // Iterating through the buckets
         pbktIn = APR_BUCKET_NEXT(pbktIn))
    {

     const char *data;
     int len;
     char *buf;
     int n;
     apr_bucket *pbktOut;
     int lengths;

// Checking if it is End-of Stream bucket
     if(APR_BUCKET_IS_EOS(pbktIn))
     {
          apr_bucket *pbktEOS=apr_bucket_eos_create(c->bucket_alloc);
          APR_BRIGADE_INSERT_TAIL(pbbOut,pbktEOS);
          continue;
     }

     apr_bucket_read(pbktIn,&data,&len,APR_BLOCK_READ); //Reading the values from each bucket


// String Manipulation code that replaces the hard-coded find string with the replace string value


   if(!find_len || (p0=strstr(data,Find_string))==NULL )
   {

    buf = apr_bucket_alloc(len, c->bucket_alloc);
      memset(buf,0,len);

      for(n=0 ; n < len ; n++)
            buf[n] = data[n];
     lengths=len;     
     goto out;     
   }


    if(diff>0 && (p3=strstr(data,Find_string))!=NULL)
    {
      dist+=diff;
       
       while(diff>0 && (p3=strstr(++p3,Find_string))!=NULL)
       {
        dist+=diff;
       
       }
    }


    if(diff<0 && (p3=strstr(data,Find_string))!=NULL)
    {
      dist1+=diff1;
       
       while(diff<0 && (p3=strstr(++p3,Find_string))!=NULL)
       {
        dist1+=diff1;
      
       }
    }

     lengths=len+dist;

     buf = apr_bucket_alloc(lengths, c->bucket_alloc);
     memset(buf,0,lengths);
   
     for(n=0 ; n < len ; n++)
              buf[n] = data[n];


     if(dist>0 && (p0=strstr(buf,Find_string))!=NULL) // if extra space needed -then insert it
     {
      
      memmove(p0+dist,p0,strlen(buf)-(p0-buf)+1);

     }

     else
        p0=strstr(buf,Find_string);

     p1=(diff>0)?p0+dist+find_len:p0+find_len;
         
     p2=strstr(p1,Find_string);   

    while(p2!=NULL) // while there is another string to replace
     {
            memcpy(p0,Replace_string,repl_len); // insert replacement
            p0+=repl_len;
            memmove(p0,p1,p2-p1); // Move only the right segment
            p0+=(p2-p1);
            p1=p2+find_len;
            p2=strstr(p1,Find_string);
     }
   
   memcpy(p0,Replace_string,repl_len); // Final Replacement


   if(diff<0) // If there is a gap at the end of str
   {
          p0+=repl_len;
          p2=strchr(p1,'\0');
          memmove(p0,p1,p2-p1+1);
          lengths=strlen(data)-dist1;
  }
    
out:

// Passing it through the next filter in the filter chain

     pbktOut = apr_bucket_heap_create(buf, lengths, apr_bucket_free,
                                         c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(pbbOut,pbktOut);
     
     }


    apr_brigade_cleanup(pbbIn);
    return ap_pass_brigade(f->next,pbbOut);
}


// Setting the configuration value based on httpd.conf string
static const char *scriptnonceFilterEnable(cmd_parms *cmd, void *cfg,const char *arg)
{
     nonce_config *config=ap_get_module_config(cmd->server->module_config,&script_nonce_filter_module);

    if(!strcasecmp(arg, "on"))
           config->on = 1;
    else config->on = 0;

    return NULL;
}

// Directives to set up the required configuration
static const command_rec scriptnonceFilterCmds[] =
{
     AP_INIT_TAKE1("NonceFilter",scriptnonceFilterEnable, NULL, RSRC_CONF, "If Enabled then do CSP script nonce filtering"),
     { NULL }
};

// Registering hooks
static void scriptnonceFilterRegisterHooks(apr_pool_t *p)
{
    ap_hook_insert_filter(scriptnonceFilterInsertFilter,NULL,NULL,APR_HOOK_MIDDLE);
    
    ap_register_output_filter(Filter_name,scriptnonceFilterOutFilter,NULL,AP_FTYPE_RESOURCE);
}

// Module declaration
module AP_MODULE_DECLARE_DATA script_nonce_filter_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,/* per-directory config creator */ 
    NULL,/* directory config merger */ 
    scriptnonceFilterCreateServerConfig,/* server config creator */  
    NULL,   /* server config merger */ 
    scriptnonceFilterCmds,/* command table */
    scriptnonceFilterRegisterHooks  /* other request processing hooks */   
};

