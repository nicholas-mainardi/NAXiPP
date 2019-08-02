grammar RFC5280;

options{
	language = C;
	output=AST;
}

@includes{
#define PCRE2_CODE_UNIT_WIDTH 8
#include<string.h>
#include<gmp.h>
#include<pcre2.h>
#include<openssl/x509.h>
#include<openssl/x509v3.h>
#include "../gen_parser_src/RFC5280.h"
#define NID_pSpecified 935
#define NID_dhpublicnumber 920
}


@lexer::members{
#include<time.h>
#define _empty NULL
#define CERT_SIGN_ASN1_ENCODING_ERROR 50
#define printf(...)
#define exit(code) do{fprintf(stdout,"0");exit(code);}while(0)
int counter_primitive = 0;
int oid = 0;
int constructed_octet = 0;
int constructed_bit = 0;
int key_usage = 0;
int dsa_counter = -1;
int ecdsa_counter = -1;
int pss_constructed_bit_flag = 1;


unsigned int compute_length(char* bytes)
{
	if((unsigned char) bytes[0] < 128)
		return (unsigned int) bytes[0];
	unsigned int value = 0;
	int i;
	unsigned int position = 1;
	int length = (unsigned char) bytes[0] -128;
	for(i=length;i>0;i--)
	{
		value += ((unsigned char) bytes[i])*position;
		position *= 256;
	}
	return value;

}
}


/*@lexer::apifuncs{
	RECOGNIZER->displayRecognitionError = errorHandling ;
	RECOGNIZER->getMissingSymbol = missingHandling;
	RECOGNIZER->mismatch = mismatchHandling;
}


@lexer::postinclude{
void errorHandling (pANTLR3_BASE_RECOGNIZER recognizer,pANTLR3_UINT8 * tokenNames);
void* missingHandling (pANTLR3_BASE_RECOGNIZER recognizer, pANTLR3_INT_STREAM istream, pANTLR3_EXCEPTION e, ANTLR3_UINT32 expectedTokenType, pANTLR3_BITSET_LIST follow);
void mismatchHandling (pANTLR3_BASE_RECOGNIZER recognizer, ANTLR3_UINT32 ttype, pANTLR3_BITSET_LIST follow);
        	
}*/




@parser::apifuncs{
	RECOGNIZER->displayRecognitionError = errorHandling ;
	RECOGNIZER->getMissingSymbol = missingHandling;
	RECOGNIZER->mismatch = mismatchHandling;
}



@parser::postinclude{
    int warning = 0;
    cert_info* cert;
/*RFC5280Parser_prog_return *tree;*/
    #ifdef DEBUG
    rule *rule_list;
    RULE_TREE *rule_tree;
    int tree_depth = -1;
    pRFC5280Parser parser_ctx=NULL;
    const char * alg_id_oids[18] = {"RSAPSSOID","SHA1DSAOID","SHA1RSAOID","SHA1ECOID","SHA224RSAOID","SHA224ECOID","SHA224DSAOID","SHA256DSAOID","SHA256ECOID",
    	"SHA256RSAOID","SHA384ECOID","SHA384RSAOID","SHA512RSAOID","SHA512ECOID","MD2RSAOID","MD5RSAOID","GOST01SIGN","GOST94SIGN"};
    const char * int_tokens[4] = {"Int0","Int1","Int2","IntTag"};
    const char * wrong_string_tags[8] = {"OIDCOUNTRY","OIDSERIAL","OIDDNQUALIFIER","LEGACYEMAILOID","AppTag1","AppTag2","ConstructedTag2","ConstructedTag1"};
    const char * string_tags[8] = {"UTF8Tag","NumericStringTag","VisibleStringTag","UniverStringTag","TeletexTag","PrintStringTag","IA5StringTag","BMPTag"};
    const char * string_rules[10] = {"utf8String","visibleString","univerString","teletexString","printString","numericString","ia5String","displayTextString","directoryString","bmpString"};
    const char * dn_oids[15] = {"OIDCN","OIDON","NAMEOID","SURNAMEOID","OIDINIT","OIDGENQUALIFIER","OIDLOCAL","OIDSORP","OIDOU","OIDTITLE","OIDDNQUALIFIER","OIDCOUNTRY",
    	"OIDSERIAL","OIDPSEUDO","OIDGIVENAME"};
    const char * tag_tokens[9] = {"Tag0","Tag1","Tag2","Tag3","Tag4","Tag5","Tag6","Tag7","Tag8"};
    const char * not_bc_rules[11] = {"notDependentExts","extensionsNotBC","extensionsNotBCNotKeyUsage","extensionsNotBCNotKeyUsageNotSki"
    ,"extensionsNotBCNotKeyUsageNotSkiNoSubAlt","extensionsNotBCNotKeyUsageNotSkiSubAlt","extensionsNotBCNotKeyUsageSubAlt","extensionsNotBCNotSki"
    ,"extensionsNotBCNotSkiSubAlt","extensionsNotBCSubAlt","extensionsNotBCNotKeyUsageNotSkiNoSubAlt"};
    const char * extension_oids[17] = {"OIDAKI","OIDSKI","OIDCERTPOL","OIDKEYUS","OIDPOLMAP","OIDSUBALT","OIDISSALT","OIDSUBDIR","OIDBC","OIDNAME","OIDPOLCONST"
    ,"OIDEXTKEY","OIDCRL","OIDINHIBIT","OIDFRESHCRL","AIAOID","SIAOID"};
    
    void push_rule(char *func);
    void pop_rule();
    int lookahead(int i,pRFC5280Parser ctx);
    
   /*int max=0;

   ANTLR3_UCHAR max_lookahead(int n,pRFC5280Parser ctx)
   {
        if(n > max)
		max = n;
   	return ctx->pParser->tstream->istream->_LA(ctx->pParser->tstream->istream, n);
   }*/
    int rule_list_lookup(rule *rule_list,char *rule)
    {
    	int found = 0;
    	while(rule_list != NULL)
    	{
    		if(!strcmp(rule_list->fname,rule))
    		{
    			found = 1;
    			break;
    		}
    		rule_list = rule_list->next;
    	}
    	return found;
    }

    int search_token(char **tokens,int length,char *item)
    {
    	int i,found = 0;
    	for(i=0;i<length;i++)
    	{
    		if(!strcmp(tokens[i],item))
    		{
    			found=1;
    			break;
    		}
    	}
    	return found;
    }
    
    int search_lookahead(int start, int end, char *token,pANTLR3_UINT8 * tokenNames)
    {
    	for(start;start<=end;start++)
    	{
    		if(!strcmp(token,tokenNames[lookahead(start,parser_ctx)]))
    		{
    			return 1;
    		}
    	}
    	return 0;
    }
    
    #endif
    
    void errorHandling (pANTLR3_BASE_RECOGNIZER recognizer,pANTLR3_UINT8 * tokenNames)
    {
    	printf("It's parser error \n");
        pANTLR3_EXCEPTION e = recognizer->state->exception;
        printf("Error occured at line \%d, in character \%d \n",e->line,e->charPositionInLine);
        int i;
        pANTLR3_COMMON_TOKEN token = (pANTLR3_COMMON_TOKEN) e->token;
        pANTLR3_STACK st = recognizer->getRuleInvocationStack(recognizer);
        if(st!=NULL)
        	printf("rule is \%s \n",st->pop(st));
            printf("Expected token was \%s and actual is \%s \n",recognizer->state->text,tokenNames[token->type]);
        printf("Rule was \%s \n",(char*) e->ruleName);
        printf("message is \%s \n",(char*) e->message);
        #ifdef DEBUG
        printf("Rule is \%s \n",rule_list->fname);
        if(rule_tree->depth > tree_depth)
        {
        push_rule("error");
        pop_rule();
        }
        printf("Parsed elements of current rule are: \n");
        rule *iterator = rule_tree->rule_list;
        while(iterator != NULL)
        {
        	printf("\%s - ",iterator->fname);
        	iterator=iterator->next;
        }
        printf("analyzing lookahead: \%x \n",parser_ctx);
        for(i=-1;i<4;i++)
        	printf("\%s - ",tokenNames[lookahead(i,parser_ctx)]);
        /*printf("Tree is \%x \n",tree->tree);
        printf("Tree is \%s \n",tree->tree->toStringTree(tree->tree)->chars);*/
       	if(!strcmp(rule_list->fname,"extensionsMustBeCAandSki") && search_token(alg_id_oids,18,tokenNames[lookahead(3,parser_ctx)]) && 
        	!(rule_list_lookup(rule_tree->rule_list,"subjectKeyId") && rule_list_lookup(rule_tree->rule_list,"bcoid")))
        	exit(MISSING_CRITICAL_BC_SKI_ERROR);
        if( (!strcmp(rule_list->fname,"extensionsNotBCNotKeyUsage") ||( !strcmp(rule_list->fname,"extensionsNotCertSignAndSki") && strcmp(tokenNames[token->type],"BitStringKeyCert"))
        	|| !strcmp(rule_list->fname,"extensionsNotBC")) && !rule_list_lookup(rule_tree->rule_list,"subjectKeyId") && search_token(alg_id_oids,18,tokenNames[lookahead(3,parser_ctx)]))
        	exit(MISSING_SKI_ERROR);
        if(!strcmp(rule_list->fname,"ads") && rule_list_lookup(rule_tree->rule_list,"ads"))
        	exit(EMPTY_ACCESS_DESCRIPTION_LIST_ERROR);
        if(!strcmp(rule_list->fname,"generalNames") && rule_list_lookup(rule_tree->rule_list,"generalNames"))
        	exit(EMPTY_GENERAL_NAMES_ERROR);
        if((!strcmp(rule_list->fname,"printable")) && strcmp(tokenNames[token->type],"Value") && strcmp(tokenNames[token->type],"Val"))
        	exit(EMPTY_PRINTABLE_STRING_ERROR);
        if((!strcmp(rule_list->fname,"tbscertificate")) && !strcmp(tokenNames[token->type],"ConstructedTag0"))
        	exit(WRONG_VERSION_ERROR);
        if((!strcmp(rule_list->fname,"extensions") && rule_list_lookup(rule_tree->rule_list,"basicConstraintsNotCritical") && !rule_list_lookup(rule_tree->rule_list->next->next,"truevalue") 
        && search_token(int_tokens,4,tokenNames[token->type])) || (!strcmp(rule_list->fname,"extensionsNoPathLen") && rule_list_lookup(rule_tree->rule_list,"basicConstraints") 
        && search_token(int_tokens,4,tokenNames[token->type])))
        	exit(PATHLEN_NO_CA_ERROR);
        if(!strcmp(rule_list->fname,"val") && !strcmp(tokenNames[lookahead(-1,parser_ctx)],"BitStringKeyCert"))
        	exit(UNEXPECTED_CERT_SIGN_BIT_ERROR);
        if((search_token(wrong_string_tags,8,tokenNames[lookahead(-1,parser_ctx)]) || search_token(string_rules,10,rule_list->fname)) && search_token(string_tags,8,tokenNames[token->type]))	        
        	exit(WRONG_STRING_TYPE_ERROR);
        if(cert->version < 3 && !strcmp(tokenNames[token->type],"ConstructedTag3") && !strcmp(tokenNames[lookahead(3,parser_ctx)],"OIDTag"))
        	exit(EXTENSION_NO_VERSION3_ERROR);
        if(!strcmp(rule_list->fname,"dn") &&  !search_token(dn_oids,15,tokenNames[lookahead(2,parser_ctx)]) && strstr(tokenNames[lookahead(2,parser_ctx)],"OID"))
        	exit(DN_WRONG_OID);
        if(!strcmp(rule_list->fname,"val") && strstr(tokenNames[lookahead(-1,parser_ctx)],"Tag"))
        	exit(EMPTY_VALUE_ERROR);
        if(!strcmp(rule_list->fname,"extensionsNotCertSignAndSki") && search_token(int_tokens,4,tokenNames[token->type]))
        {
        	if(!strcmp(tokenNames[lookahead(-1,parser_ctx)],"TrueTag"))
        		exit(PATHLEN_NO_BC_CRITICAL_ERROR);
        	else
        		exit(PATHLEN_NO_CA_ERROR);
        }
        if(!strcmp(rule_list->fname,"extensionsCertSignAndSki") && search_token(alg_id_oids,18,tokenNames[lookahead(3,parser_ctx)]))
        	exit(MISSING_SKI_AND_CERT_SIGN_ERROR);
        if(!strcmp(rule_list->fname,"constructedOctetString") && !strcmp(tokenNames[token->type],"TrueTag"))
        	exit(CRITICAL_EXTENSION_ERROR);
        if(search_token(tag_tokens,9,tokenNames[token->type]) && strcmp("VALUE",tokenNames[lookahead(2,parser_ctx)]) && strcmp("Val",tokenNames[lookahead(2,parser_ctx)]) 
        && strcmp("PRINTABLE",tokenNames[lookahead(2,parser_ctx)]))
        	exit(EMPTY_NUMERIC_TAG_ERROR);
        if(!strcmp(rule_list->fname,"policyQualifiers") &&  strcmp("UNOTICEOID",tokenNames[lookahead(3,parser_ctx)]) && strcmp("CPSOID",tokenNames[lookahead(3,parser_ctx)]) 
        && strstr(tokenNames[lookahead(3,parser_ctx)],"OID"))
        	exit(POLICY_WRONG_OID_ERROR);
        if(!strcmp(rule_list->fname,"policies") && strstr(tokenNames[lookahead(3,parser_ctx)],"OID"))
        	exit(POLICY_WRONG_OID_ERROR);
        if(!strcmp(rule_list->fname,"extensionsCertSign") && search_token(alg_id_oids,18,tokenNames[lookahead(3,parser_ctx)]))
        	exit(MISSING_CERT_SIGN_ERROR);        	
        if(!strcmp(rule_list->fname,"generalSubtrees") && rule_list_lookup(rule_tree->rule_list,"generalSubtrees"))
        	exit(GENERAL_SUBTREES_EMPTY_ERROR);
        if(!strcmp(rule_list->fname,"tbscertificate") && !strcmp("OIDTag",tokenNames[lookahead(2,parser_ctx)]) && !strcmp("VALUE",tokenNames[lookahead(3,parser_ctx)]))
        	exit(WRONG_ALG_ID_OID_ERROR);
        if(search_token(not_bc_rules,11,rule_list->fname) && !strcmp(tokenNames[lookahead(3,parser_ctx)],"OIDBC"))	
        	exit(REPEATED_BC_ERROR);
        if(rule_list_lookup(rule_tree->rule_list,"subjectPKinfo") && (!strcmp(rule_list->fname,"extensions") || !strcmp(rule_list->fname,"extensionsWithSubAlt")))
        	exit(EMPTY_EXTENSIONS_LIST_ERROR);
        if(strstr(rule_list->fname,"extension") && !search_token(extension_oids,17,tokenNames[lookahead(3,parser_ctx)]) && strstr(tokenNames[lookahead(3,parser_ctx)],"OID"))
        	exit(EXTENSION_WRONG_OID_ERROR);
        /*if(rule_list->next && rule_list->next->next && !strcmp(rule_list->next->next->fname,"issuer") && !strcmp(tokenNames[token->type],"Null") && (strstr(cert->signature_algorithm->oid->ln,"Pss") || !strstr(cert->signature_algorithm->oid->ln,"RSA")) 
        && !strstr(cert->signature_algorithm->oid->ln,"GOST"))*/
	if(rule_list->next && rule_list->next->next && !strcmp(rule_list->next->next->fname,"issuer") && !strcmp(tokenNames[token->type],"Null") && (strstr(OBJ_nid2ln(OBJ_obj2nid(cert->signature_algorithm->oid)),"Pss") || !strstr(OBJ_nid2ln(OBJ_obj2nid(cert->signature_algorithm->oid)),"RSA")) 
        && !strstr(OBJ_nid2ln(OBJ_obj2nid(cert->signature_algorithm->oid)),"GOST"))
        	exit(UNEXPECTED_NULL_ALG_ID_PARAMS_ERROR);
        if(search_token(int_tokens,4,tokenNames[token->type]) && search_lookahead(-5,0,"OIDBC",tokenNames))
        	if(!search_lookahead(-2,0,"TrueTag",tokenNames))
        		exit(PATHLEN_NO_CA_ERROR);
        	else
        		exit(PATHLEN_NO_BC_CRITICAL_ERROR);
        if(!strcmp(rule_list->fname,"prog") && rule_list_lookup(rule_tree->rule_list,"certificate"))
		exit(END_OF_CERT_EXPECTED_ERROR);
	#endif
        exit(GENERIC_ERROR);
    }
    
    static pANTLR3_UINT8* getTokenNames();
    void* missingHandling (pANTLR3_BASE_RECOGNIZER recognizer, pANTLR3_INT_STREAM istream, pANTLR3_EXCEPTION e, ANTLR3_UINT32 expectedTokenType, pANTLR3_BITSET_LIST follow)
    {
    	pANTLR3_UINT8* tokenNames = getTokenNames();
    	printf("Expected token is \%s \n",tokenNames[expectedTokenType]);
    	pANTLR3_COMMON_TOKEN token = (pANTLR3_COMMON_TOKEN) e->token;
            	printf("actual token is \%s \n",tokenNames[token->type]);
        	printf("Rule was \%s \n",(char*) e->ruleName);
        	printf("message is \%s \n",(char*) e->message);
        	#ifdef DEBUG
        	printf("Rule is \%s \n",rule_list->fname);
        	if(rule_tree->depth > tree_depth)
        	{
        		push_rule("error");
       		pop_rule();
        	}
        	printf("Parsed elements of current rule are: \n");
        	rule *iterator = rule_tree->rule_list;
        	while(iterator != NULL)
        	{
        		printf("\%s - ",iterator->fname);
        		iterator=iterator->next;
        	}
        	if(!strcmp(tokenNames[token->type],"ConstructedOctetTag") && !strcmp(tokenNames[expectedTokenType],"TrueTag"))
        		exit(BC_NOT_CRITICAL_ERROR);
        	if((search_token(alg_id_oids,18,tokenNames[token->type]) && !strcmp(tokenNames[expectedTokenType],"OIDBC")) || 
        	(rule_list_lookup(rule_tree->rule_list,"bcoid") && !strcmp(rule_list->fname,"truevalue") && !strcmp(tokenNames[token->type],"FalseTag")))
        		if(!rule_list_lookup(rule_tree->rule_list,"constructedOctetString"))
        			exit(BC_NOT_CRITICAL_ERROR);	
        		else
        			exit(MISSING_CA_ERROR);
        	if(!strcmp(tokenNames[token->type],"SequenceTag") && !strcmp(tokenNames[expectedTokenType],"ConstructedTag3"))
        		exit(MISSING_EXTENSION_TAG3_ERROR);
        	if(search_token(int_tokens,4,tokenNames[token->type]) && !strcmp(tokenNames[lookahead(-1,parser_ctx)],"TrueTag") && !strcmp(tokenNames[lookahead(-3,parser_ctx)],"ConstructedOctetTag")
        	&& (!strcmp(tokenNames[lookahead(-4,parser_ctx)],"OIDBC") || !strcmp(tokenNames[lookahead(-5,parser_ctx)],"OIDBC")))
        		exit(PATHLEN_NO_BC_CRITICAL_ERROR);	
        	if(!strcmp(rule_list->fname,"set") && !strcmp(rule_list->next->fname,"rdnsNotEmpty") && !strcmp(rule_list->next->next->fname,"notEmptyName") 
        	&& !strcmp(tokenNames[expectedTokenType],"SetTag"))
        		exit(EMPTY_RDNS_ERROR);
        	printf("analyzing lookahead: \%x \n",parser_ctx);
              	int i;
        	for(i=-5;i<8;i++)
        		printf("\%s - ",tokenNames[lookahead(i,parser_ctx)]);        		
    	
    	#endif
    	exit(GENERIC_ERROR);
    }
    
    void mismatchHandling (pANTLR3_BASE_RECOGNIZER recognizer, ANTLR3_UINT32 ttype, pANTLR3_BITSET_LIST follow)
    {
    	pANTLR3_EXCEPTION e = recognizer->state->exception;
    	pANTLR3_UINT8* tokenNames = getTokenNames();
    	printf("Expected token is \%s \n",tokenNames[ttype]);
    	pANTLR3_COMMON_TOKEN token = (pANTLR3_COMMON_TOKEN) e->token;
            	printf("actual token is \%s \n",tokenNames[token->type]);
        	printf("Rule was \%s \n",(char*) e->ruleName);
        	printf("message is \%s \n",(char*) e->message);
    	exit(1);
    }
}

@parser::members{
#define _empty NULL


oid_list *exts_list;
oid_list *policies_list;

counter *counter_list;
counter *set_pointer;
counter *any_pointer;
counter *sequence_pointer;
counter *general_name_pointer;
cert_info cert_init = {1,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,0,0,255,0,NULL};
struct asn1_string_st *default_salt;
struct asn1_string_st *default_trailer;
ASN1_OBJECT *default_encryption;
STACK_OF(X509_DNAME_ENTRY) *dname;
GEN_NAME *gen_name;
const unsigned char data_salt[1] = {20};
const unsigned char data_trailer[1] = {1};
const unsigned char min_base_distance[1]={0};
x509_EXTENSION *key_usage_ext;
x509_EXTENSION *bc_ext;
unsigned char eku_mask = 0;
int ca_repo = 0;
int tsp = 0;

unsigned int compute_len(char* bytes,mpz_t value)
{
	if((unsigned char) bytes[1] < 128)
	{
		mpz_add_ui(value,value,(unsigned int) bytes[1]);
		return 2;
	}
	mpz_t bytevalue,position;
	mpz_init(bytevalue);
	mpz_init_set_ui(position,1);
	int i;
	int len = (unsigned char) bytes[1] - 128;
	for(i=len+1;i>1;i--)
	{
		mpz_mul_ui(bytevalue,position,(unsigned char) bytes[i]);
		mpz_add(value,value,bytevalue);
		mpz_mul_ui(position,position,256);
		//value += ((unsigned char) bytes[i])*position;
		//position *= 256;
	}
	return len+2;
}


void compute_integer(char* bytes,mpz_t length,mpz_t value)
{
	mpz_t bytevalue,position,i;
	mpz_init(bytevalue);
	mpz_init_set_ui(position,1);
	mpz_init_set(i,length);
	for(mpz_sub_ui(i,i,1);mpz_cmp_ui(i,0)>0;mpz_sub_ui(i,i,1))
	{
		mpz_mul_ui(bytevalue,position,(unsigned char) bytes[mpz_get_ui(i)]);
		mpz_add(value,value,bytevalue);
		mpz_mul_ui(position,position,256);
		/*value += ((unsigned char) bytes[i])*position;
		position *= 256;*/
	}
	mpz_mul_si(bytevalue,position,bytes[0]);
	mpz_add(value,value,bytevalue);
}


int compute_oid_value(char *bytes,int len,mpz_t *test)
{
    int i=1;
    if((unsigned char) bytes[len-1] > 127)
    	exit(BAD_OID_TERMINATOR_ERROR);
    if((unsigned char) bytes[0]<128)
    if ((unsigned char) bytes[0] < 40)
    {
        mpz_init_set_ui(test[0],0);
        mpz_init_set_ui(test[1],(unsigned char) bytes[0]);
    }
    else if ((unsigned char) bytes[0] < 80)
    {
        mpz_init_set_ui(test[0],1);
        mpz_init_set_ui(test[1],(unsigned char) bytes[0]-40);
    }
    else
    {
        mpz_init_set_ui(test[0],2);
        mpz_init_set_ui(test[1],(unsigned char) bytes[0]-80);
    }
    else
    {
        mpz_init_set_ui(test[0],2);
        mpz_init_set_ui(test[1],(unsigned char) bytes[0]-128);
        for(i=1;i<len;i++)
        {
        if((unsigned char) bytes[i] < 128)
        {
            //test[1] = 128*test[1] + (unsigned char) argv[i];
            mpz_mul_ui(test[1],test[1],128);
            mpz_add_ui(test[1],test[1],(unsigned char) bytes[1]);
	    if(mpz_cmp_ui(test[1],268435455)>0)
	    	exit(OID_ARC_OVERFLOW_ERROR);
	    i++;
            break;
        }
        else
        {
            //test[1] = 128*test[1] + ((unsigned char) argv[i]) - 128;
            mpz_mul_ui(test[1],test[1],128);
            mpz_add_ui(test[1],test[1],(unsigned char) bytes[1] -128);
        
        }
        }
        mpz_sub_ui(test[1],test[1],80);
    }
    int j = 2;
    mpz_init_set_ui(test[2],0);
    for(i;i<len;i++)
    {
        if((unsigned char) bytes[i] < 128)
        {
            mpz_mul_ui(test[j],test[j],128);
            mpz_add_ui(test[j],test[j],(unsigned char) bytes[i]);
            if(mpz_cmp_ui(test[j],268435455)>0)
	    	exit(OID_ARC_OVERFLOW_ERROR);
	    j++;
            mpz_init_set_ui(test[j],0);
        }
        else
        {
            mpz_mul_ui(test[j],test[j],128);
            mpz_add_ui(test[j],test[j],(unsigned char) bytes[i] -128);
        }
    }
    return j;
}

void carnot_mapping(mpz_t x,mpz_t y)
{
    mpz_t sum;
    mpz_init(sum);
    mpz_add(sum,x,y);
    mpz_mul(x,sum,sum);
    mpz_add(x,x,sum);
    mpz_div_ui(x,x,2);
    mpz_add(x,x,y);
}

void compute_index(mpz_t* oid,unsigned long len,mpz_t index)
{
unsigned long  j;
mpz_init_set(index,oid[0]);
    for(j=1;j<len;j++)
    {
        carnot_mapping(index,oid[j]);
    }
}

void compute_bitstring (char *value,unsigned long length,ASN1_STRING *bs)
{
	if((unsigned char) value[0] > 8)
		exit(BAD_BITSTRING_ENCODING_ERROR);
	unsigned char mask = 255 << (unsigned char) value[0];
	bs->type=3;
	bs->length = length-1;
	bs->data = malloc(bs->length);
	unsigned long i;
	value[bs->length] &= mask;
	for(i=0;i<bs->length;i++)
		bs->data[i] = value[i+1];
	free(value);
}

void check_asn1_string(ASN1_STRING *str)
{

	switch(str->type)
	{
	case 19: 	{
		char pattern[100]="^([A-Z]|[a-z]|[0-9]|\\x20|\\-|\\/|\\+|\\(|\\)|:|=|\\?|\\.|,|')+\\z";
		if(check_string(pattern,str->data,str->length))
		{
			printf("Error in Printable String \%s \n",str->data);
			exit(PRINT_STRING_REGEXP_ERROR);
		}
		}	break;
	case 22:	{
		char pattern[20] = "^[\\x01-\\x7F]+$";
		if(check_string(pattern,str->data,str->length))
		{
			printf("Error in Ia5String \%s \n",str->data);
			exit(IA5_STRING_REGEXP_ERROR);
		}
		}	break;
	case 30:	{
		char pattern[250]=
"^(\\x00[\\x01-\\xFF]|[\\x01-\\x07][\\x00-\\xFF]|\\x08([\\x00-\\x5F]|[\\xA0-\\xFF])|[\\x09-\\x1B][\\x00-\\xFF]|\\x1C([\\x00-\\x7F]|[\\xC0-\\xFF])|[\\x1D-\\x2E][\\x00-\\xFF]|\\x2F([\\x00-\\xDF]|[\\xF0-\\xFF])|[\\x30-\\xD7][\\x00-\\xFF]|[\\xE0-\\xFF][\\x00-\\xFF])+$";
		if(check_string(pattern,str->data,str->length))
		{
			printf("Error in BMP String \%s \n",str->data);
			exit(BMP_STRING_REGEXP_ERROR);
		}
		}	break;
	case 18:	{
		char pattern[50]="^([A-Z]|[a-z]|[0-9]|\\x20)+\\z";
		if(check_string(pattern,str->data,str->length))
		{
			printf("Error in Numeric String \%s \n",str->data);
			exit(NUMERIC_STRING_REGEXP_ERROR);
		}
		}	break;
	case 20:	{
		char pattern[250] = "^([\\x01-\\x22]|[\\x25-\\x5B]|\\x5D|\\x5F|[\\x61-\\x7A]|\\x7C|[\\x7F-\\xA8]|\\xAB|[\\xB0-\\xB8]|[\\xBB-\\xBF]|[\\xC1-\\xC8]|[\\xCA-\\xCF]|[\\xE0-\\xE4]|[\\xE6-\\xFE])+$";
		if(check_string(pattern,str->data,str->length))
		{
			printf("Error in Teletex String \%s \n",str->data);
			exit(T61_STRING_REGEXP_ERROR);
		}
		}	break;
	case 26:	{
		char pattern[20]="^[\\x20-\\x7F]+\\z";
		if(check_string(pattern,str->data,str->length))
		{
			printf("Error in Visible String \%s \n",str->data);
			exit(VISIBLE_STRING_REGEXP_ERROR);
		}
		}	break;
	default:	break;
	}
}

struct asn1_string_st * new_asn1_string(int type,int length,char* data)
{
		struct asn1_string_st *text;
		text = malloc(sizeof(struct asn1_string_st));
		text->type = type;
		text->length = length;
		text->data = (unsigned char *) data;
		check_asn1_string(text);
		return text;
}

int cmp_asn1_string(struct asn1_string_st *first_op,struct asn1_string_st *second_op)
{
	if(first_op->type != second_op->type)
		return 0;
	if(first_op->length != second_op->length)
		return 0;
	int i;
	for(i=0;i<first_op->length;i++)
	{
		if(first_op->data[i] != second_op->data[i])
			return 0;
	}
	return 1;
}

void new_alg_id(ASN1_OBJECT *obj)
{
cert->signature_algorithm = malloc(sizeof(ALG_ID));
cert->signature_algorithm->oid = obj;
cert->signature_algorithm->params=NULL;
}

void new_alg_id_pk(ASN1_OBJECT *obj)
{
cert->pkey->alg = malloc(sizeof(ALG_ID));
cert->pkey->alg->oid = obj;
cert->pkey->alg->params=NULL;
}

void new_rsa_pk(ASN1_INTEGER *n,ASN1_INTEGER *e)
{
	cert->pkey->pubkey = malloc(sizeof(PUBKEY));
	cert->pkey->pubkey->rsa = malloc(sizeof(RSA_KEY));
	cert->pkey->pubkey->rsa->n = n;
	cert->pkey->pubkey->rsa->e = e;
}

new_bitstring_pk(ASN1_STRING *bs)
{
	cert->pkey->pubkey = malloc(sizeof(PUBKEY));
	cert->pkey->pubkey->bitstring_encoding = bs;
}

int check_string(char *pattern_string,char *sub,unsigned long size)
{
    pcre2_code *re;
    PCRE2_SPTR pattern;
    PCRE2_SPTR subject;
    int errornumber,rc;
    PCRE2_SIZE erroroffset;
    pcre2_match_data *match_data;
    
    subject = (PCRE2_SPTR) sub;
    pattern = (PCRE2_SPTR) pattern_string;
    //fprintf(stdout,"\%s \n",pattern_string);
    re = pcre2_compile(pattern,PCRE2_ZERO_TERMINATED,0,&errornumber,&erroroffset,NULL);
    //fprintf(stdout,"\%d \%d \n",errornumber,erroroffset);
    match_data = pcre2_match_data_create_from_pattern(re, NULL);
    rc = pcre2_match(re,subject,size,0,0,match_data,NULL);
    pcre2_match_data_free(match_data);
    pcre2_code_free(re);
    return rc<0;
}

void insert_extension(mpz_t index)
{
	if(exts_list == NULL)
	{
	exts_list = malloc(sizeof(oid_list));
	mpz_init_set(exts_list->index,index);
	exts_list->next = NULL;
	}
	else
	{
	oid_list *el,*previous = NULL;
	el = exts_list;
	while(el != NULL)
	{
		int outcome = mpz_cmp(index,el->index);
		if(outcome<0)
		{
			//printf("Outcome < 0 \n");
			oid_list *new = malloc(sizeof(oid_list));
			mpz_init_set(new->index,index);
			new->next=el;
			if(previous != NULL)
				previous->next=new;
			else
				exts_list=new;
			//printf("Return \n");
			return;
		}
		else if(outcome == 0)
		{
			gmp_printf("Duplicated oid with index \%Zd \n",index);
			exit(DUPLICATED_EXTENSION);
		}
		previous = el;
		el = el->next;
	}
	oid_list *new = malloc(sizeof(oid_list));
	mpz_init_set(new->index,index);
	previous->next = new;
	new->next = NULL;
	}
}

void insert_policy(mpz_t index)
{
	if(policies_list == NULL)
	{
	policies_list = malloc(sizeof(oid_list));
	mpz_init_set(policies_list->index,index);
	policies_list->next = NULL;
	}
	else
	{
	oid_list *el,*previous = NULL;
	el = policies_list;
	while(el != NULL)
	{
		int outcome = mpz_cmp(index,el->index);
		if(outcome<0)
		{
			//printf("Outcome < 0 \n");
			oid_list *new = malloc(sizeof(oid_list));
			mpz_init_set(new->index,index);
			new->next=el;
			if(previous != NULL)
				previous->next=new;
			else
				policies_list=new;
			//printf("Return \n");
			return;
		}
		else if(outcome == 0)
		{
			gmp_printf("Duplicated oid with index \%Zd \n",index);
			exit(DUPLICATED_POLICY);
		}
		previous = el;
		el = el->next;
	}
	oid_list *new = malloc(sizeof(oid_list));
	mpz_init_set(new->index,index);
	previous->next = new;
	new->next = NULL;
	}
}

int store_value(char *value,int i,char **s,int len)
{
		int j,z;
		for(j=0;j<len;j++)
		{
		(*s)[i]=(unsigned char) value[j];i++;
		if(i\%16==0)
		{
			char *t = malloc(16+i);
			for(z=0;z<i;z++)
				t[z]=(*s)[z];
			free(*s);
			*s=t;
		}
		}
		return i;
}
#ifdef DEBUG
void update_rule_tree()
{
if(rule_tree == NULL)
{
	rule_tree = malloc(sizeof(RULE_TREE));
	rule_tree->rule_list = malloc(sizeof(rule));
	rule_tree->rule_list->fname = rule_list->fname;
	rule_tree->rule_list->next = NULL;
	rule_tree->next =  NULL;
	rule_tree->depth = tree_depth;
}
else 	if(rule_tree->depth == tree_depth)
	{
		rule *rule_item = malloc(sizeof(rule));
		rule_item->fname = rule_list->fname;
		rule_item->next = NULL;
		rule *iterator = rule_tree->rule_list;
		while(iterator->next != NULL)
			iterator = iterator->next;
		iterator->next = rule_item;
	}
	else if(rule_tree->depth < tree_depth)
	{
		RULE_TREE *new_item = malloc(sizeof(RULE_TREE));
		new_item->depth = tree_depth;
		new_item->next=rule_tree;
		new_item->rule_list=malloc(sizeof(rule));
		new_item->rule_list->fname=rule_list->fname;
		new_item->rule_list->next=NULL;
		rule_tree = new_item;
	}
	else
	{
		RULE_TREE *old_item = rule_tree;
		rule_tree = old_item->next;
		rule *iterator = old_item->rule_list;
		rule *current_item;
		while(iterator != NULL)
		{
			current_item = iterator;
			iterator = iterator->next;
			free(current_item);
		}
		free(old_item);
		update_rule_tree();
	}
}

void push_rule(char *func)
{
	printf("i'm in push rule \%s \n",func);
	if(rule_list == NULL)
	{
		rule_list = malloc(sizeof(rule));
		//counter_list->counter = length;
		rule_list->fname=func;
		rule_list->next = NULL;
	}
	else
	{
		rule *new_rule=malloc(sizeof(rule));
		new_rule->fname=func;
		new_rule->next=rule_list;
		rule_list=new_rule;
	}
	tree_depth++;
	update_rule_tree();	
}

void pop_rule()
{
if(rule_list!=NULL)
{
	rule *old_rule=rule_list;
	rule_list=rule_list->next;
	printf("pop rule \%s \n",old_rule->fname);
	free(old_rule);
	tree_depth--;
}
else
{
printf("pop null \n");
exit(0);
}
}

int lookahead(int i,pRFC5280Parser ctx)
{
	return LA(i);
}

#endif

void push(mpz_t length,int length_field)
{	
		gmp_printf("\%Zd is sequence length \n",length);
		if(counter_list == NULL)
		{
			counter_list = malloc(sizeof(counter));
			//counter_list->counter = length;
			mpz_init_set(counter_list->counter,length);
			counter_list->next = NULL;
		}
		else
		{
			counter* new_counter = malloc(sizeof(counter));
			/*new_counter->counter = length;
			new_counter->start_counter = length;
			new_counter->start_counter += length_field;*/
			mpz_init_set(new_counter->counter,length);
			mpz_init_set(new_counter->start_counter,length);
			mpz_add_ui(new_counter->start_counter,new_counter->start_counter,length_field);
			new_counter->next = counter_list;
			counter_list = new_counter;
		}
}

void check_and_pop(mpz_t len,int length_field)
{
if(counter_list != NULL)
	{
	//counter_list->counter -= len +length_field;
	mpz_sub(counter_list->counter,counter_list->counter,len);
	mpz_sub_ui(counter_list->counter,counter_list->counter,length_field);
	gmp_printf("Sequence length is \%Zd and length field is \%d and length subtracted is \%Zd \n",counter_list->counter,length_field,len);
	int outcome = mpz_cmp_ui(counter_list->counter,0);
	if(outcome < 0)
	{
		printf("Sequence Length not ok \n");
		exit(SEQUENCE_LENGTH_ERROR);
	}
	else if(outcome == 0)
	{
		printf("Sequence Length ok \n");
		counter* old_counter = counter_list;
		counter_list = counter_list->next;
		if(counter_list!= NULL)
		check_and_pop(old_counter->start_counter,0);
		if(set_pointer == old_counter)
			set_pointer = NULL;
		if(any_pointer == old_counter)
			any_pointer = NULL;
		if(sequence_pointer == old_counter)
		{	
			printf("Sequence pointer nulled \n");
			sequence_pointer = NULL;
		}
		if(general_name_pointer == old_counter)
		{
			general_name_pointer = NULL;
		}
		free(old_counter); 
	}
	}	
}

void primitive_tag(char *val,mpz_t length,int length_field)
{
	/*int i;
	int len = strlen(val);
	for(i=0;i<length;i++)
		printf("\%x \n", (unsigned char) val[i]);
	if(len == length)
		printf("length ok \n");
	else
		printf("length not ok \n");*/
	check_and_pop(length,length_field);
}

void primitive_type(char *val,mpz_t length)
{
		int len =compute_len(val,length);
		check_and_pop(length,len);	
}

void constructed_type(char *val)
{
		mpz_t length;
		mpz_init_set_ui(length,0);
		int len =compute_len(val,length);
		if (mpz_cmp_ui(length,0)>0)
			push(length,len);
		else
			check_and_pop(length,len);
}

void entire_encoding(unsigned int length)
{
	mpz_t len;
	mpz_init_set_ui(len,length);
	check_and_pop(len,2);
}

void populate_string_table()
{
ASN1_STRING_TABLE_add(NID_pseudonym,1,ub_pseudonym,DIRSTRING_TYPE,0);
ASN1_STRING_TABLE_add(NID_generationQualifier,1,ub_name,DIRSTRING_TYPE,0);
ASN1_STRING_TABLE_add(NID_title,1,ub_title,DIRSTRING_TYPE,0);

}

void keyusage_check()
{
	if(key_usage_ext == NULL || key_usage_ext->value->keyusage == NULL)
		return;
	unsigned char keyus = (unsigned char) key_usage_ext->value->keyusage->data[0];
	unsigned char mask;
	if(cert->is_ca)
		mask = cert->mask_ca;
	else
		mask = cert->mask;
	cert->eku_mask |= eku_mask;
	printf("key us is \%d and mask is \%d and eku is \%d \n",keyus,mask,cert->eku_mask);	
	if(keyus & mask)
	{
		printf("Error on key usage CA Constraint \n");
		exit(KEY_USAGE_CONSTRAINT_ERROR);
	}
	if(keyus & ~cert->eku_mask)
	{
		warning|=UNCONSISTENT_USAGE_FOUND_WARNING;
	}
	if(!(keyus & cert->eku_mask))
		warning|=NO_CONSISTENT_USAGE_FOUND_WARNING;
	if(keyus & 255)
	{
		if(key_usage_ext->value->keyusage->length > 1 && (((unsigned char) key_usage_ext->value->keyusage->data[1]) & 128))
		{
			if((keyus & 8) && !(keyus & 1));
			else
			{
				printf("Error on key agreement constraint about decypher only \n");
				exit(KEY_AGREEMENT_DECYPHER_ONLY_ERROR);	
			}
		}
		else
		{ 
			if(((unsigned char) keyus & 9) == 0x01)
			{
				printf("Error on key agreement constraint about encypher only \n");
				exit(KEY_AGREEMENT_ENCYPHER_ONLY_ERROR);					
			}
			else;
		}	
	}
	else
	{
		printf("At least one bit must be set in key usage \n");
		exit(KEY_USAGE_NO_BITS_SET);
	}
	//if everything is ok, add key usage to extensions stack
	sk_x509_EXTENSION_push(cert->extensions,key_usage_ext);
}

int compare_dn_entries(X509_DNAME_ENTRY *issuer,X509_DNAME_ENTRY *subject)
{
	const int nids[16] = {NID_commonName,NID_organizationName,NID_name,NID_surname,NID_givenName,NID_initials,NID_generationQualifier,NID_localityName,NID_organizationalUnitName,
	NID_stateOrProvinceName,NID_title,NID_pseudonym,NID_dnQualifier,NID_countryName,NID_serialNumber,NID_pkcs9_emailAddress};
	int j;
	for(j=0;j<16;j++)
	{
		if(OBJ_obj2nid(issuer->string_name->oid) == nids[j])
			break;
	}
	if(j!=16)
	{
		if(cmp_asn1_string(issuer->string_name->value,subject->string_name->value))
			return 1;
		else
			return 0;
	}
	else
	{
		ANY* issuer_iter = issuer->other_name->value;
		ANY* subject_iter = subject->other_name->value;
		while(issuer_iter && subject_iter)
		{
			if(sizeof(*(issuer_iter->el)) == sizeof(*(subject_iter->el)))
			{
				if(sizeof(*(subject_iter->el)) == sizeof(ASN1_STRING))
					if(!cmp_asn1_string((ASN1_STRING *) subject_iter->el,(ASN1_STRING *) issuer_iter->el))
						return 0;
				else 
				{
				ASN1_OBJECT *issuer_obj = (ASN1_OBJECT *) issuer_iter->el;
				ASN1_OBJECT *subject_obj = (ASN1_OBJECT *)subject_iter->el;
				if( OBJ_obj2nid(issuer_obj) != OBJ_obj2nid(subject_obj))
					return 0;
				}
			}
			else
				return 0;
			issuer_iter = issuer_iter->next;
			subject_iter = subject_iter->next;
		}
		if(issuer_iter == subject_iter)
			return 1;
		else
			return 0;
	}	
}

int compare_dn(STACK_OF(X509_DNAME_ENTRY *issuer),STACK_OF(X509_DNAME_ENTRY) *subject)
{
	int i,num,j,z;
	num = sk_X509_DNAME_ENTRY_num(issuer);
	printf("num is \%d \n",num);
	if(num == sk_X509_DNAME_ENTRY_num(subject))
	{	
		int *subject_indexes =  malloc(sizeof(int)*num);
		for(i=0;i<num;i++)
		{
			X509_DNAME_ENTRY *issuer_entry = sk_X509_DNAME_ENTRY_value(issuer,i);
			X509_DNAME_ENTRY *subject_entry;
			for(j=0;j<i;j++)
				if(i == subject_indexes[j])
					break;
			if(j == i)
			{
				subject_entry = sk_X509_DNAME_ENTRY_value(subject,i);
				if(OBJ_obj2nid(issuer_entry->string_name->oid) == OBJ_obj2nid(subject_entry->string_name->oid))
				{
					if(compare_dn_entries(issuer_entry,subject_entry))
					{
						subject_indexes[i]=i;
						continue;
					}
				}
			}
			for(j=i+1;i != j \% num;j++)
			{
				for(z=0;z<i;z++)
					if(j \% num == subject_indexes[z])
						break;
				if(z == i)
				{
					subject_entry = sk_X509_DNAME_ENTRY_value(subject,j \% num);
					if(OBJ_obj2nid(issuer_entry->string_name->oid) == OBJ_obj2nid(subject_entry->string_name->oid))
						if(compare_dn_entries(issuer_entry,subject_entry))
						{
							subject_indexes[i]=j \% num;	
							break;
						}		
				}
			}
			printf("i is \%d and \%d \n",i,j\%num);
			if(i == j \% num)
				return 0;
		}
		return 1;
	}
	else
		return 0;
}

void check_aki()
{
	if(cert->version > 2 && !cert->key_id)
	{
		int self_signed = compare_dn(cert->issuer,cert->subject);
		if(!self_signed)
			exit(MISSING_AKI_KEY_ID_ERROR);
	}
}

void print_cert_info()
{
	printf("version is \%d \n",cert->version);
	if(cert->serial_number)
		printf("serial number is \%s \n",cert->serial_number->data);
	printf("signature algorithm is \%s \n",OBJ_nid2ln(OBJ_obj2nid(cert->signature_algorithm->oid)));
	printf("Val time is \%d \%s , \%d \%s \n",cert->validity->notBefore->type,cert->validity->notBefore->data,cert->validity->notAfter->type,cert->validity->notAfter->data);
	printf("Issuer is \%s \n",X509_NAME_oneline(cert->issuer,NULL,0));
	printf("Subject is \%s \n",X509_NAME_oneline(cert->subject,NULL,0));
	printf("Public key is \%s \n",cert->pkey->pubkey->bitstring_encoding->data);
	printf("Public key params is \%s \n",OBJ_nid2ln(OBJ_obj2nid(cert->pkey->alg->params->ecpk->named_curve)));
	printf("Signature is \%s \%s \n",cert->signature->dsa_sign->r->data,cert->signature->dsa_sign->s->data);
	printf("Certificate is CA? \%d \n",bc_ext->value->basic_constraints->is_ca);
}
void final_check()
{
while(counter_list != NULL)
	{
		if(counter_list->counter != 0)
		{
			printf("Sequence length not ok \n");
			exit(SEQUENCE_LENGTH_ERROR);
		}
		counter_list = counter_list->next;
	}
	/*oid_list *el;
	el = exts_list;
	while(el != NULL)
	{
		gmp_printf("\%Zd   ",el->index);
		el = el->next;
	}
	printf("\n");*/
	keyusage_check();
	check_aki();
	if(ca_repo && !cert->is_ca)
		warning |= CA_REPO_NO_CA_WARNING;
	if(tsp && cert->is_ca)
		warning |= TSP_CA_WARNING;
	/*print_cert_info();*/
	printf("parsing Completed \n");
	//exit(0);
}


void compute_names()
{
	int i,counter=0;
	X509_DNAME_ENTRY* dname;
	for(i=0;i < sk_X509_DNAME_ENTRY_num(cert->subject);i++)
	{
		dname = sk_X509_DNAME_ENTRY_value(cert->subject,i);
		if(OBJ_obj2nid(dname->string_name->oid) == NID_commonName)
			counter++;
	}
	X509_EXTENSION_VALUE *extn;
	GEN_NAME *gen_name;
	for(i=0;i < sk_x509_EXTENSION_num(cert->extensions);i++)
	{
		//fprintf(stdout,"Looking for exntesions \n");
		x509_EXTENSION* ext = sk_x509_EXTENSION_value(cert->extensions,i); 
		if(OBJ_obj2nid(ext->oid)==NID_subject_alt_name)
		{
			extn = ext->value;
			int j,z;
			for(j=0;j < sk_GENERAL_NAME_POINTER_num(extn->gen_names);j++)
			{
				gen_name = sk_GENERAL_NAME_POINTER_value(extn->gen_names,j);
				if(gen_name->tag == 1 || gen_name->tag == 2 || gen_name->tag == 6 || gen_name->tag == 7)
					counter++;
				else if(gen_name->tag == 4)
				{
					for(z=0;z < sk_X509_DNAME_ENTRY_num(gen_name->name->dn);z++)
					{
						dname = sk_X509_DNAME_ENTRY_value(gen_name->name->dn,z);
						if(OBJ_obj2nid(dname->string_name->oid) == NID_commonName)
							counter++;
					}
					/*int lastpos=-1;
					int index = X509_NAME_get_index_by_NID(gen_name->name->dn,NID_commonName,lastpos); 
					fprintf(stdout,"Here \%d \n",index);
					while(index != -1)
					{
						if(index == -2)
						{
							fprintf(stdout,"wrong nid \n");
							exit(255);
						}
						counter++;
						lastpos = index;
						index = X509_NAME_get_index_by_NID(gen_name->name->dn,NID_commonName,lastpos); 
					}*/
				}
			}
		}
	}
	fprintf(stdout,"Names: \%d",counter);
}


}
prog 	:	{#ifdef DEBUG 
		push_rule(__func__);
		parser_ctx = ctx; 
		#endif
	cert = malloc(sizeof(cert_info));*cert= cert_init;cert->extensions=NULL;populate_string_table();ASN1_STRING_TABLE *tbl = ASN1_STRING_TABLE_get(NID_pseudonym);printf("tbl min is \%d and max is \%d \n",tbl->minsize,tbl->maxsize);}certificate EOF 
	{
	if(!bc_ext)
		cert->is_ca=0;
	else
	{
		sk_x509_EXTENSION_push(cert->extensions,bc_ext);
		cert->is_ca = bc_ext->value->basic_constraints->is_ca;
		if(bc_ext->value->basic_constraints->pathlen != NULL)
		{
		mpz_t value,length;
		mpz_init_set_ui(value,0);
		mpz_init_set_ui(length,bc_ext->value->basic_constraints->pathlen->length);
		compute_integer(bc_ext->value->basic_constraints->pathlen->data,length,value);
		if(mpz_sgn(value) == -1)
			exit(NEGATIVE_PATHLEN_ERROR);
		}
	}
	final_check();
	//compute_names();
	#ifdef DEBUG
	printf("rule is \%s \n",rule_list->fname);
	pop_rule(); 
	#endif};

certificate @after{#ifdef DEBUG
	pop_rule(); 
	#endif} : {#ifdef DEBUG 
	push_rule(__func__); 
	#endif} sequenceTag 
	{
	extern int counter_primitive,max;
	if(counter_primitive > 0)
		exit(TRUNCATED_FILE_ERROR);
	//printf("max lookahead is \%d \n",max);
	
	}
	tbscertificate {printf("after EOF \n");};
	
tbscertificate @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	: {#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	sequenceTag 
	(constructedTag0 version3 serialnumber 
(rsa_md2_alg_id issuer validity (subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)? (constructedTag3 sequenceTag {printf("before ext \n");}extensions )?
		     |sequenceTag subjectPKinfo (issueruniqueId)? (subjectuniqueId)? constructedTag3 sequenceTag extensionsWithSubAlt ) rsa_md2_alg_id signature
|rsa_md5_alg_id issuer validity (subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)? (constructedTag3 sequenceTag {printf("before ext \n");}extensions )?
		     |sequenceTag subjectPKinfo (issueruniqueId)? (subjectuniqueId)? constructedTag3 sequenceTag extensionsWithSubAlt ) rsa_md5_alg_id signature
|rsa_sha1_alg_id issuer validity (subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)? (constructedTag3 sequenceTag {printf("before ext \n");}extensions )?
		     |sequenceTag subjectPKinfo (issueruniqueId)? (subjectuniqueId)? constructedTag3 sequenceTag extensionsWithSubAlt ) rsa_sha1_alg_id signature
|rsa_sha224_alg_id issuer validity (subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)? (constructedTag3 sequenceTag {printf("before ext \n");}extensions )?
		     |sequenceTag subjectPKinfo (issueruniqueId)? (subjectuniqueId)? constructedTag3 sequenceTag extensionsWithSubAlt ) rsa_sha224_alg_id signature
|rsa_sha256_alg_id issuer validity (subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)? (constructedTag3 sequenceTag {printf("before ext \n");}extensions )?
		     |sequenceTag subjectPKinfo (issueruniqueId)? (subjectuniqueId)? constructedTag3 sequenceTag extensionsWithSubAlt ) rsa_sha256_alg_id signature
|rsa_sha384_alg_id issuer validity (subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)? (constructedTag3 sequenceTag {printf("before ext \n");}extensions )?
		     |sequenceTag subjectPKinfo (issueruniqueId)? (subjectuniqueId)? constructedTag3 sequenceTag extensionsWithSubAlt ) rsa_sha384_alg_id signature
|rsa_sha512_alg_id issuer validity (subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)? (constructedTag3 sequenceTag {printf("before ext \n");}extensions )?
		     |sequenceTag subjectPKinfo (issueruniqueId)? (subjectuniqueId)? constructedTag3 sequenceTag extensionsWithSubAlt ) rsa_sha512_alg_id signature
|dsa_sha_alg_id issuer validity (subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)? (constructedTag3 sequenceTag {printf("before ext \n");}extensions )?
		     |sequenceTag subjectPKinfo (issueruniqueId)? (subjectuniqueId)? constructedTag3 sequenceTag extensionsWithSubAlt ) dsa_sha_alg_id dsa_signature
|ec_sha_alg_id issuer validity (subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)? (constructedTag3 sequenceTag {printf("before ext \n");}extensions )?
		     |sequenceTag subjectPKinfo (issueruniqueId)? (subjectuniqueId)? constructedTag3 sequenceTag extensionsWithSubAlt ) ec_sha_alg_id dsa_signature
|pss_alg_id_params issuer validity (subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)? (constructedTag3 sequenceTag {printf("before ext \n");}extensions )?
		     |sequenceTag subjectPKinfo (issueruniqueId)? (subjectuniqueId)? constructedTag3 sequenceTag extensionsWithSubAlt ) pss_alg_id_params signature
|dsa_sha224_alg_id issuer validity (subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)? (constructedTag3 sequenceTag {printf("before ext \n");}extensions )?
		     |sequenceTag subjectPKinfo (issueruniqueId)? (subjectuniqueId)? constructedTag3 sequenceTag extensionsWithSubAlt ) dsa_sha224_alg_id dsa_signature
|dsa_sha256_alg_id issuer validity (subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)? (constructedTag3 sequenceTag {printf("before ext \n");}extensions )?
		     |sequenceTag subjectPKinfo (issueruniqueId)? (subjectuniqueId)? constructedTag3 sequenceTag extensionsWithSubAlt ) dsa_sha256_alg_id dsa_signature
|ec_sha224_alg_id issuer validity (subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)? (constructedTag3 sequenceTag {printf("before ext \n");}extensions )?
		     |sequenceTag subjectPKinfo (issueruniqueId)? (subjectuniqueId)? constructedTag3 sequenceTag extensionsWithSubAlt ) ec_sha224_alg_id dsa_signature
|ec_sha256_alg_id issuer validity (subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)? (constructedTag3 sequenceTag {printf("before ext \n");}extensions )?
		     |sequenceTag subjectPKinfo (issueruniqueId)? (subjectuniqueId)? constructedTag3 sequenceTag extensionsWithSubAlt ) ec_sha256_alg_id dsa_signature
|ec_sha384_alg_id issuer validity (subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)? (constructedTag3 sequenceTag {printf("before ext \n");}extensions )?
		     |sequenceTag subjectPKinfo (issueruniqueId)? (subjectuniqueId)? constructedTag3 sequenceTag extensionsWithSubAlt ) ec_sha384_alg_id dsa_signature
|ec_sha512_alg_id issuer validity (subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)? (constructedTag3 sequenceTag {printf("before ext \n");}extensions )?
		     |sequenceTag subjectPKinfo (issueruniqueId)? (subjectuniqueId)? constructedTag3 sequenceTag extensionsWithSubAlt ) ec_sha512_alg_id dsa_signature
|gost_94_alg_id issuer validity (subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)? (constructedTag3 sequenceTag {printf("before ext \n");}extensions )?
		     |sequenceTag subjectPKinfo (issueruniqueId)? (subjectuniqueId)? constructedTag3 sequenceTag extensionsWithSubAlt ) gost_94_alg_id signature
|gost_01_alg_id issuer validity (subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)? (constructedTag3 sequenceTag {printf("before ext \n");}extensions )?
		     |sequenceTag subjectPKinfo (issueruniqueId)? (subjectuniqueId)? constructedTag3 sequenceTag extensionsWithSubAlt ) gost_01_alg_id signature

)
	
	|	constructedTag0 version2 serialnumber 
	(rsa_md2_alg_id issuer validity subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)?  rsa_md2_alg_id signature
	|rsa_md5_alg_id issuer validity subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)?  rsa_md5_alg_id signature
	|rsa_sha1_alg_id issuer validity subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)?  rsa_sha1_alg_id signature
	|rsa_sha224_alg_id issuer validity subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)?  rsa_sha224_alg_id signature
	|rsa_sha256_alg_id issuer validity subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)?  rsa_sha256_alg_id signature
	|rsa_sha384_alg_id issuer validity subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)?  rsa_sha384_alg_id signature
	|rsa_sha512_alg_id issuer validity subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)?  rsa_sha512_alg_id signature
	|dsa_sha_alg_id issuer validity subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)?  dsa_sha_alg_id dsa_signature
	|ec_sha_alg_id issuer validity subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)?  ec_sha_alg_id dsa_signature	
	|pss_alg_id_params issuer validity subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)?  pss_alg_id_params signature
	|dsa_sha224_alg_id issuer validity subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)?  dsa_sha224_alg_id dsa_signature
	|dsa_sha256_alg_id issuer validity subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)?  dsa_sha256_alg_id dsa_signature
	|ec_sha224_alg_id issuer validity subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)?  ec_sha224_alg_id dsa_signature
	|ec_sha256_alg_id issuer validity subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)?  ec_sha256_alg_id dsa_signature
	|ec_sha384_alg_id issuer validity subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)?  ec_sha384_alg_id dsa_signature
	|ec_sha512_alg_id issuer validity subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)?  ec_sha512_alg_id dsa_signature
	|gost_94_alg_id issuer validity subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)?  gost_94_alg_id signature
	|gost_01_alg_id issuer validity subject subjectPKinfo (issueruniqueId)? (subjectuniqueId)?  gost_01_alg_id signature
	)	

	|	(constructedTag0 version)? serialnumber
	(rsa_md2_alg_id issuer validity subject subjectPKinfo rsa_md2_alg_id signature 
	|rsa_md5_alg_id issuer validity subject subjectPKinfo rsa_md5_alg_id signature
	|rsa_sha1_alg_id issuer validity subject subjectPKinfo rsa_sha1_alg_id signature
	|rsa_sha224_alg_id issuer validity subject subjectPKinfo rsa_sha224_alg_id signature
	|rsa_sha256_alg_id issuer validity subject subjectPKinfo rsa_sha256_alg_id signature
	|rsa_sha384_alg_id issuer validity subject subjectPKinfo rsa_sha384_alg_id signature
	|rsa_sha512_alg_id issuer validity subject subjectPKinfo rsa_sha512_alg_id signature
	|dsa_sha_alg_id issuer validity subject subjectPKinfo dsa_sha_alg_id dsa_signature
	|ec_sha_alg_id issuer validity subject subjectPKinfo ec_sha_alg_id dsa_signature
	|pss_alg_id_params issuer validity subject subjectPKinfo pss_alg_id_params signature
	|dsa_sha224_alg_id issuer validity subject subjectPKinfo dsa_sha224_alg_id dsa_signature
	|dsa_sha256_alg_id issuer validity subject subjectPKinfo dsa_sha256_alg_id dsa_signature
	|ec_sha224_alg_id issuer validity subject subjectPKinfo ec_sha224_alg_id dsa_signature
	|ec_sha256_alg_id issuer validity subject subjectPKinfo ec_sha256_alg_id dsa_signature
	|ec_sha384_alg_id issuer validity subject subjectPKinfo ec_sha384_alg_id dsa_signature
	|ec_sha512_alg_id issuer validity subject subjectPKinfo ec_sha512_alg_id dsa_signature
	|gost_94_alg_id issuer validity subject subjectPKinfo gost_94_alg_id signature
	|gost_01_alg_id issuer validity subject subjectPKinfo gost_01_alg_id signature)
	
	);

algorithm_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	: {#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	sequenceTag {any_pointer = counter_list;} oid  ({any_pointer != NULL}?=> any| );
	
rsa_md2_alg_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	: {#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag md2rsaoid null?{
	if(cert->signature_algorithm == NULL)
		new_alg_id($md2rsaoid.obj);
	};	
	
rsa_md5_alg_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag md5rsaoid null?{
	if(cert->signature_algorithm == NULL)
		new_alg_id($md5rsaoid.obj);
	};	

rsa_sha1_alg_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag sha1rsaoid null?{
	if(cert->signature_algorithm == NULL)
		new_alg_id($sha1rsaoid.obj);
	};	
	

rsa_sha224_alg_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag sha224rsaoid null?{
	if(cert->signature_algorithm == NULL)
		new_alg_id($sha224rsaoid.obj);
	};	


rsa_sha256_alg_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag sha256rsaoid null?{
	if(cert->signature_algorithm == NULL)
		new_alg_id($sha256rsaoid.obj);
	};	

rsa_sha384_alg_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag sha384rsaoid null?{
	if(cert->signature_algorithm == NULL)
		new_alg_id($sha384rsaoid.obj);
	};	

rsa_sha512_alg_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag sha512rsaoid null?{
	if(cert->signature_algorithm == NULL)
		new_alg_id($sha512rsaoid.obj);
	};	

dsa_sha_alg_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag sha1dsaoid {
		if(cert->signature_algorithm == NULL)
			new_alg_id($sha1dsaoid.obj);	
	};
	

dsa_sha224_alg_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag sha224dsaoid {
		if(cert->signature_algorithm == NULL)
			new_alg_id($sha224dsaoid.obj);	
	}(sequenceTag i1=integer i2=integer i3=integer{if(cert->signature_algorithm->params == NULL)
	{
		cert->signature_algorithm->params = malloc(sizeof(alg_id_params));
		cert->signature_algorithm->params->dsa.p=$i1.text;
		cert->signature_algorithm->params->dsa.q=$i2.text;
		cert->signature_algorithm->params->dsa.g=$i3.text;
	}
	else
	{
		if(!cmp_asn1_string(cert->signature_algorithm->params->dsa.p,$i1.text) || !cmp_asn1_string(cert->signature_algorithm->params->dsa.q,$i2.text) || !cmp_asn1_string(cert->signature_algorithm->params->dsa.g,$i3.text))
		{
			printf("Error! Signature parameters doesn't match \n");
			exit(DSA_SIGNATURE_PARAMS_MATCHING_ERROR);		
		}
	}
	})?;

dsa_sha256_alg_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag sha256dsaoid {
		if(cert->signature_algorithm == NULL)
			new_alg_id($sha256dsaoid.obj);
	}(sequenceTag i1=integer i2=integer i3=integer {if(cert->signature_algorithm->params == NULL)
	{
		cert->signature_algorithm->params = malloc(sizeof(alg_id_params));
		cert->signature_algorithm->params->dsa.p=$i1.text;
		cert->signature_algorithm->params->dsa.q=$i2.text;
		cert->signature_algorithm->params->dsa.g=$i3.text;
	}
	else
	{
		if(!cmp_asn1_string(cert->signature_algorithm->params->dsa.p,$i1.text) || !cmp_asn1_string(cert->signature_algorithm->params->dsa.q,$i2.text) || !cmp_asn1_string(cert->signature_algorithm->params->dsa.g,$i3.text))
		{
			printf("Error! Signature parameters doesn't match \n");
			exit(DSA_SIGNATURE_PARAMS_MATCHING_ERROR);		
		}
	}
	})?;

ec_sha_alg_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag sha1ecoid{
	if(cert->signature_algorithm == NULL)
		new_alg_id($sha1ecoid.obj);
	};
ec_sha224_alg_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag sha224ecoid{
	if(cert->signature_algorithm == NULL)
		new_alg_id($sha224ecoid.obj);
			};	
ec_sha256_alg_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag sha256ecoid {
	if(cert->signature_algorithm == NULL)
		new_alg_id($sha256ecoid.obj);
			};	
ec_sha384_alg_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag sha384ecoid{
	if(cert->signature_algorithm == NULL)
		new_alg_id($sha384ecoid.obj);
	};		
ec_sha512_alg_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag sha512ecoid{
	if(cert->signature_algorithm == NULL)
		new_alg_id($sha512ecoid.obj);
	};		

rsa_alg_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag rsapkoid null?{
	new_alg_id_pk($rsapkoid.obj);
	};
	
dsa_alg_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag dsapkoid{new_alg_id_pk($dsapkoid.obj);} (sequenceTag i1=integer i2=integer i3=integer{
		cert->pkey->alg->params =  malloc(sizeof(alg_id_params));
		cert->pkey->alg->params->dsa.p = $i1.text;
		cert->pkey->alg->params->dsa.q = $i2.text;
		cert->pkey->alg->params->dsa.g = $i3.text;
	})?;
	
dh_alg_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag dhpkoid {new_alg_id_pk($dhpkoid.obj);} sequenceTag p=integer g=integer q=integer
	{
		cert->pkey->alg->params = malloc(sizeof(alg_id_params));
		cert->pkey->alg->params->dh.p = $p.text;
		cert->pkey->alg->params->dh.g = $g.text;
		cert->pkey->alg->params->dh.q = $q.text;
		cert->pkey->alg->params->dh.j = NULL;
		cert->pkey->alg->params->dh.seed = NULL;
		cert->pkey->alg->params->dh.pgen_counter = NULL;
	}
	
	 (j=integer {cert->pkey->alg->params->dh.j = $j.text;}( |sequenceTag bitstring pgen=integer {
	 cert->pkey->alg->params->dh.seed = $bitstring.text;
	 cert->pkey->alg->params->dh.pgen_counter = $pgen.text;
	 }))?;
	
kea_alg_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag keapkoid octetstring {
	new_alg_id_pk($keapkoid.obj);
	cert->pkey->alg->params = malloc(sizeof(alg_id_params));
	if($octetstring.text->length != 10)
	{
		printf("Error on kea domain identifier length \n");
		exit(KEA_DOMAINID_LENGTH_ERROR);
	}
	cert->pkey->alg->params->kea.domain_id = $octetstring.text;
	};

ec_alg_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag (ecpkoid {new_alg_id_pk($ecpkoid.obj);cert->mask = 54;cert->mask_ca=48;}
		|ecdhoid {new_alg_id_pk($ecdhoid.obj);cert->mask = 246;cert->mask_ca=246;}
		| ecmqvoid {new_alg_id_pk($ecmqvoid.obj);cert->mask = 246;cert->mask_ca=246;}) oid {
	cert->pkey->alg->params = malloc(sizeof(alg_id_params));
	cert->pkey->alg->params->ecpk = malloc(sizeof(ecpk_params));
	cert->pkey->alg->params->ecpk->named_curve = $oid.text->obj;
	} ;
	
ecParams @after{#ifdef DEBUG
	pop_rule(); 
	#endif}	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag int1{
	cert->pkey->alg->params = malloc(sizeof(alg_id_params));
	cert->pkey->alg->params->ecpk = malloc(sizeof(ecpk_params));
	cert->pkey->alg->params->ecpk->ec = malloc(sizeof(ec_params));
	}  field_id a=octetstring b=octetstring (bitstring {cert->pkey->alg->params->ecpk->ec->seed = $bitstring.text;})? base=octetstring order=integer (cofactor=integer{
	cert->pkey->alg->params->ecpk->ec->cofactor = $cofactor.text;
	})?
	{
	cert->pkey->alg->params->ecpk->ec->a = $a.text;
	cert->pkey->alg->params->ecpk->ec->b = $b.text;
	cert->pkey->alg->params->ecpk->ec->base = $base.text;
	cert->pkey->alg->params->ecpk->ec->order = $order.text;
	};

field_id 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:
		primeoid integer {cert->pkey->alg->params->ecpk->ec->field = malloc(sizeof(FIELD_ID));
	cert->pkey->alg->params->ecpk->ec->field->field_type = $primeoid.obj;
	cert->pkey->alg->params->ecpk->ec->field->field_params = malloc(sizeof(field_params));
	cert->pkey->alg->params->ecpk->ec->field->field_params->p = $integer.text;
	} | basis2oid m=integer {cert->pkey->alg->params->ecpk->ec->field = malloc(sizeof(FIELD_ID));
	cert->pkey->alg->params->ecpk->ec->field->field_type = $basis2oid.obj;
	cert->pkey->alg->params->ecpk->ec->field->field_params = malloc(sizeof(field_params));
	cert->pkey->alg->params->ecpk->ec->field->field_params->char_two = malloc(sizeof(characteristic_two));
	cert->pkey->alg->params->ecpk->ec->field->field_params->char_two->m = $m.text;
	} (gnoid null {cert->pkey->alg->params->ecpk->ec->field->field_params->char_two->basis = $gnoid.obj;} | tpoid tri=integer 
	{cert->pkey->alg->params->ecpk->ec->field->field_params->char_two->basis = $tpoid.obj;
	cert->pkey->alg->params->ecpk->ec->field->field_params->char_two->char_two_params = malloc(sizeof(char_two_params));
	cert->pkey->alg->params->ecpk->ec->field->field_params->char_two->char_two_params->trinomial = $tri.text;
	}
	| ppoid sequenceTag k1=integer k2=integer k3=integer {cert->pkey->alg->params->ecpk->ec->field->field_params->char_two->basis = $ppoid.obj;
	cert->pkey->alg->params->ecpk->ec->field->field_params->char_two->char_two_params = malloc(sizeof(char_two_params));
	cert->pkey->alg->params->ecpk->ec->field->field_params->char_two->char_two_params->pentanomial = malloc(sizeof(penta_params));
	cert->pkey->alg->params->ecpk->ec->field->field_params->char_two->char_two_params->pentanomial->k1 = $k1.text;
	cert->pkey->alg->params->ecpk->ec->field->field_params->char_two->char_two_params->pentanomial->k2 = $k2.text;
	cert->pkey->alg->params->ecpk->ec->field->field_params->char_two->char_two_params->pentanomial->k3 = $k3.text;
	}| oid any {cert->pkey->alg->params->ecpk->ec->field->field_params->char_two->basis = $oid.text->obj;
	cert->pkey->alg->params->ecpk->ec->field->field_params->char_two->char_two_params = malloc(sizeof(char_two_params));
	cert->pkey->alg->params->ecpk->ec->field->field_params->char_two->char_two_params->any = $any.text; 
	}) | oid any {cert->pkey->alg->params->ecpk->ec->field = malloc(sizeof(FIELD_ID));
	cert->pkey->alg->params->ecpk->ec->field->field_type = $oid.text->obj;
	cert->pkey->alg->params->ecpk->ec->field->field_params =  malloc(sizeof(field_params));
	cert->pkey->alg->params->ecpk->ec->field->field_params->any = $any.text;
	};
	
pss_alg_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag rsapssoid {
		new_alg_id_pk($rsapssoid.obj);
		cert->pkey->alg->params = malloc(sizeof(alg_id_params));
		cert->pkey->alg->params->pss.hash_func= NULL;
		cert->pkey->alg->params->pss.mgf1_hash_func=NULL;
		cert->pkey->alg->params->pss.salt_length=NULL;
		cert->pkey->alg->params->pss.trailer_field=NULL;
		} (sequenceTag (constructedTag0 hash_alg {
		cert->pkey->alg->params->pss.hash_func = $hash_alg.alg ;
		})? (constructedTag1 mask_gen_alg {
		cert->pkey->alg->params->pss.mgf1_hash_func = $mask_gen_alg.alg ;
		})? (constructedTag2 salt=integer{
		cert->pkey->alg->params->pss.salt_length = $salt.text;
		})? (constructedTag3 trailer=integer{
		cert->pkey->alg->params->pss.trailer_field = $trailer.text;
		})? )?
		{
		if(!cert->pkey->alg->params->pss.hash_func)
			cert->pkey->alg->params->pss.hash_func = OBJ_nid2obj(NID_sha1);
		if(!cert->pkey->alg->params->pss.mgf1_hash_func)
			cert->pkey->alg->params->pss.mgf1_hash_func = OBJ_nid2obj(NID_sha1);
		if(!cert->pkey->alg->params->pss.salt_length)
		{
			if(!default_salt)
				default_salt = new_asn1_string(2,1,data_salt);
			cert->pkey->alg->params->pss.salt_length = default_salt;
		}
		if(!cert->pkey->alg->params->pss.trailer_field)
		{
			if(!default_trailer)
				default_trailer = new_asn1_string(2,1,data_trailer);
			cert->pkey->alg->params->pss.salt_length = default_trailer;
		}
		};

pss_alg_id_params @after{#ifdef DEBUG
	pop_rule(); 
	#endif} @init{int check = 0;
		if(default_salt == NULL)
			default_salt = new_asn1_string(2,1,data_salt);
		if(default_trailer == NULL)
			default_trailer = new_asn1_string(2,1,data_trailer);
		#ifdef DEBUG 
		push_rule(__func__); 
		#endif	
			}
	:	sequenceTag rsapssoid {
		if(cert->signature_algorithm == NULL)
		{
		new_alg_id($rsapssoid.obj);
		cert->signature_algorithm->params = malloc(sizeof(alg_id_params));
		cert->signature_algorithm->params->pss.hash_func= NULL;
		cert->signature_algorithm->params->pss.mgf1_hash_func=NULL;
		cert->signature_algorithm->params->pss.salt_length=NULL;
		cert->signature_algorithm->params->pss.trailer_field=NULL;
		}
		else
		{
			if(OBJ_obj2nid(cert->signature_algorithm->params->pss.hash_func) != NID_sha1)
				check++;
			if(OBJ_obj2nid(cert->signature_algorithm->params->pss.mgf1_hash_func) != NID_sha1)
				check++;
			if(!cmp_asn1_string (default_salt,cert->signature_algorithm->params->pss.salt_length))
				check++;
			if(!cmp_asn1_string (default_trailer,cert->signature_algorithm->params->pss.trailer_field))
				check++;				
		}	
	}sequenceTag (constructedTag0 hash_alg 
	{if(cert->signature_algorithm->params->pss.hash_func == NULL) 
		cert->signature_algorithm->params->pss.hash_func = $hash_alg.alg;
	else if(OBJ_obj2nid(cert->signature_algorithm->params->pss.hash_func) != OBJ_obj2nid($hash_alg.alg))
	{
		printf("Error! Signature parameters doesn't match \n");
		exit(SIGNATURE_PARAMS_MATCHING_ERROR);		
	}
	if(OBJ_obj2nid(cert->signature_algorithm->params->pss.hash_func) != NID_sha1)	
		check--;
	})? (constructedTag1 mask_gen_alg
	{if(cert->signature_algorithm->params->pss.mgf1_hash_func == NULL) 
		cert->signature_algorithm->params->pss.mgf1_hash_func = $mask_gen_alg.alg;
	else if(OBJ_obj2nid(cert->signature_algorithm->params->pss.mgf1_hash_func) != OBJ_obj2nid($mask_gen_alg.alg))
	{
		printf("Error! Signature parameters doesn't match \n");
		exit(SIGNATURE_PARAMS_MATCHING_ERROR);		
	}
	if(OBJ_obj2nid(cert->signature_algorithm->params->pss.mgf1_hash_func) != NID_sha1)	
		check--;
	})? (constructedTag2 salt=integer
	{if(cert->signature_algorithm->params->pss.salt_length == NULL)
		cert->signature_algorithm->params->pss.salt_length = $salt.text;
	else
	{struct asn1_string_st *new = $salt.text; 
	if(!cmp_asn1_string(cert->signature_algorithm->params->pss.salt_length,new))
	{
		printf("Error! Signature parameters doesn't match \n");
		exit(SIGNATURE_PARAMS_MATCHING_ERROR);		
	}free(new);
	}
	if(!cmp_asn1_string (default_salt,cert->signature_algorithm->params->pss.salt_length))
		check--;
	})? (constructedTag3 trailer=integer
	{if(cert->signature_algorithm->params->pss.trailer_field == NULL)
		cert->signature_algorithm->params->pss.trailer_field= $trailer.text;
	else
	{struct asn1_string_st *new = $trailer.text; 
	if(!cmp_asn1_string(cert->signature_algorithm->params->pss.trailer_field,new))
	{
		printf("Error! Signature parameters doesn't match \n");
		exit(SIGNATURE_PARAMS_MATCHING_ERROR);		
	}free(new);
	}
	if(!cmp_asn1_string (default_trailer,cert->signature_algorithm->params->pss.trailer_field))
		check--;
	})? {
		if(check > 0)
		{
		printf("Error! Signature parameters doesn't match \n");
		exit(SIGNATURE_PARAMS_MATCHING_ERROR);		
		}
		else{
			if(cert->signature_algorithm->params->pss.hash_func == NULL)
			{
				cert->signature_algorithm->params->pss.hash_func = OBJ_nid2obj(NID_sha1);
			}
			if(cert->signature_algorithm->params->pss.mgf1_hash_func == NULL)
				cert->signature_algorithm->params->pss.mgf1_hash_func = OBJ_nid2obj(NID_sha1);
			if(cert->signature_algorithm->params->pss.salt_length == NULL)
				cert->signature_algorithm->params->pss.salt_length = default_salt;
			if(cert->signature_algorithm->params->pss.trailer_field == NULL)
				cert->signature_algorithm->params->pss.trailer_field = default_trailer;
		}
		if(!cmp_asn1_string(cert->signature_algorithm->params->pss.salt_length,default_salt))
		{
			free(default_salt);
			default_salt = NULL;
		}
		if(!cmp_asn1_string(cert->signature_algorithm->params->pss.trailer_field,default_trailer))
		{
			free(default_trailer);
			default_trailer = NULL;
		}
	};	

oaep_alg_id 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag rsaoaepoid{
		new_alg_id_pk($rsaoaepoid.obj);
		cert->pkey->alg->params = malloc(sizeof(alg_id_params));
		cert->pkey->alg->params->oaep.hash_func= NULL;
		cert->pkey->alg->params->oaep.mgf1_hash_func=NULL;
		cert->pkey->alg->params->oaep.P = NULL;
		} ( sequenceTag (constructedTag0 hash_alg{
		cert->pkey->alg->params->oaep.hash_func = $hash_alg.alg;
		})? (constructedTag1 mask_gen_alg{
		cert->pkey->alg->params->oaep.mgf1_hash_func = $mask_gen_alg.alg;
		})? (constructedTag2 sequenceTag pspecoid (octetstring{
		cert->pkey->alg->params->oaep.P = $octetstring.text;
		}
		)?)? )?
		{
		if(!cert->pkey->alg->params->oaep.hash_func)
			cert->pkey->alg->params->oaep.hash_func = OBJ_nid2obj(NID_sha1);
		if(!cert->pkey->alg->params->oaep.mgf1_hash_func)
			cert->pkey->alg->params->oaep.mgf1_hash_func = OBJ_nid2obj(NID_sha1);
		if(!cert->pkey->alg->params->oaep.P)
			cert->pkey->alg->params->oaep.P = new_asn1_string(4,0,NULL);
		}
		;

hash_alg returns [ASN1_OBJECT *alg]
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:	sequenceTag
		(sha1oid (null)? {$alg = $sha1oid.obj;}
	|	sha224oid (null)? {$alg = $sha224oid.obj;}
	|	sha256oid (null)? {$alg = $sha256oid.obj;}
	|	sha384oid (null)? {$alg = $sha384oid.obj;}
	|	sha512oid (null)? {$alg = $sha512oid.obj;})
	;
	
mask_gen_alg returns [ASN1_OBJECT *alg]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag mgf1oid hash_alg {$alg = $hash_alg.alg ;};
	
gost_94_alg_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	@init{int check=0;
	if(default_encryption == NULL)
		default_encryption = OBJ_nid2obj(NID_id_Gost28147_89_CryptoPro_A_ParamSet);
	if(cert->signature_algorithm!=NULL)
	{
		if(cert->signature_algorithm->params->gost.public_key_param_set != NULL)
			check++;
		if(OBJ_obj2nid(cert->signature_algorithm->params->gost.encryption_param_set) != OBJ_obj2nid(default_encryption))
			check++;
	}
	#ifdef DEBUG 
	push_rule(__func__); 
	#endif
	}
	:	sequenceTag gost94signoid (null | sequenceTag o1=oid o2=oid {
	if(cert->signature_algorithm == NULL)
	{
		cert->signature_algorithm =  malloc(sizeof(ALG_ID));
		cert->signature_algorithm->oid = $gost94signoid.obj;
		cert->signature_algorithm->params = malloc(sizeof(alg_id_params));
		cert->signature_algorithm->params->gost.public_key_param_set = $o1.text->obj;	
		cert->signature_algorithm->params->gost.digest_param_set = $o2.text->obj;
		cert->signature_algorithm->params->gost.encryption_param_set = NULL;
	}
	else {if(cert->signature_algorithm->params->gost.public_key_param_set != NULL && cert->signature_algorithm->params->gost.digest_param_set != NULL &&
		OBJ_obj2nid(cert->signature_algorithm->params->gost.public_key_param_set) == OBJ_obj2nid($o1.text->obj) && OBJ_obj2nid(cert->signature_algorithm->params->gost.digest_param_set) == OBJ_obj2nid($o2.text->obj))
		{
			printf("Error! Signature parameters doesn't match \n");
			exit(GOST_SIGNATURE_PARAMS_MATCHING_ERROR);		
		}
	if(cert->signature_algorithm->params->gost.public_key_param_set != NULL)
		check--;
		}
	} (o3=oid {
	if(cert->signature_algorithm->params->gost.encryption_param_set == NULL)
		cert->signature_algorithm->params->gost.encryption_param_set = $o3.text->obj;
	else {
	if(OBJ_obj2nid(cert->signature_algorithm->params->gost.encryption_param_set) !=  OBJ_obj2nid($o3.text->obj))
		{
			printf("Error! Signature parameters doesn't match \n");
			exit(GOST_SIGNATURE_PARAMS_MATCHING_ERROR);		
		}	
		if(OBJ_obj2nid(cert->signature_algorithm->params->gost.encryption_param_set) != OBJ_obj2nid(default_encryption))
			check--;}
	})?)? {
	if(cert->signature_algorithm == NULL)
	{
		new_alg_id($gost94signoid.obj);
		cert->signature_algorithm->params = malloc(sizeof(alg_id_params));
		cert->signature_algorithm->params->gost.public_key_param_set = NULL;
		cert->signature_algorithm->params->gost.digest_param_set = NULL;
		cert->signature_algorithm->params->gost.encryption_param_set = default_encryption;
	}
	else{ 
	if(cert->signature_algorithm->params->gost.encryption_param_set != default_encryption)
	{
		free(default_encryption);
		default_encryption = NULL;
	}
	if(check > 0)
		{
			printf("Error! Signature parameters doesn't match \n");
			exit(GOST_SIGNATURE_PARAMS_MATCHING_ERROR);		
		}	
	}
	};
	
gost_01_alg_id @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	@init{int check=0;
	if(default_encryption == NULL)
		default_encryption = OBJ_nid2obj(NID_id_Gost28147_89_CryptoPro_A_ParamSet);
	if(cert->signature_algorithm!=NULL)
	{
		if(cert->signature_algorithm->params->gost.public_key_param_set != NULL)
			check++;
		if(OBJ_obj2nid(cert->signature_algorithm->params->gost.encryption_param_set) != OBJ_obj2nid(default_encryption))
			check++;
	}
	#ifdef DEBUG 
	push_rule(__func__); 
	#endif
	}
	:	sequenceTag gost01signoid (null | sequenceTag o1=oid o2=oid {
	if(cert->signature_algorithm == NULL)
	{
		cert->signature_algorithm =  malloc(sizeof(ALG_ID));
		cert->signature_algorithm->oid = $gost01signoid.obj;
		cert->signature_algorithm->params = malloc(sizeof(alg_id_params));
		cert->signature_algorithm->params->gost.public_key_param_set = $o1.text->obj;	
		cert->signature_algorithm->params->gost.digest_param_set = $o2.text->obj;
		cert->signature_algorithm->params->gost.encryption_param_set = NULL;
	}
	else {if(cert->signature_algorithm->params->gost.public_key_param_set != NULL && cert->signature_algorithm->params->gost.digest_param_set != NULL &&
		OBJ_obj2nid(cert->signature_algorithm->params->gost.public_key_param_set) == OBJ_obj2nid($o1.text->obj) && OBJ_obj2nid(cert->signature_algorithm->params->gost.digest_param_set) == OBJ_obj2nid($o2.text->obj))
		{
			printf("Error! Signature parameters doesn't match \n");
			exit(GOST_SIGNATURE_PARAMS_MATCHING_ERROR);		
		}
	if(cert->signature_algorithm->params->gost.public_key_param_set != NULL)
		check--;}
	} (o3=oid {
	if(cert->signature_algorithm->params->gost.encryption_param_set == NULL)
		cert->signature_algorithm->params->gost.encryption_param_set = $o3.text->obj;
	else {
	if(OBJ_obj2nid(cert->signature_algorithm->params->gost.encryption_param_set) !=  OBJ_obj2nid($o3.text->obj))
		{
			printf("Error! Signature parameters doesn't match \n");
			exit(GOST_SIGNATURE_PARAMS_MATCHING_ERROR);		
		}
	if(OBJ_obj2nid(cert->signature_algorithm->params->gost.encryption_param_set) != OBJ_obj2nid(default_encryption))
		check--;}
	})?)?{
	if(cert->signature_algorithm == NULL)
	{
		new_alg_id($gost01signoid.obj);
		cert->signature_algorithm->params = malloc(sizeof(alg_id_params));
		cert->signature_algorithm->params->gost.public_key_param_set = NULL;
		cert->signature_algorithm->params->gost.digest_param_set = NULL;
		cert->signature_algorithm->params->gost.encryption_param_set = default_encryption;
	}
	else{ 
	if(cert->signature_algorithm->params->gost.encryption_param_set != default_encryption)
	{
		free(default_encryption);
		default_encryption = NULL;
	}
	if(check > 0)
		{
			printf("Error! Signature parameters doesn't match \n");
			exit(GOST_SIGNATURE_PARAMS_MATCHING_ERROR);		
		}
	}
	};
	
version	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	 	int0 {cert->version=1;};

version2 @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		int1 {cert->version=2;};

version3 @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		int2 {cert->version=3;};

serialnumber @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		integer {cert->serial_number=$integer.text;
		mpz_t value,length;
		mpz_init_set_ui(value,0);
		mpz_init_set_ui(length,$integer.text->length);
		if($integer.text->length > 20)
			warning |= SERIAL_NUMBER_TOO_LONG_WARNING;
		compute_integer($integer.text->data,length,value);
		if(mpz_sgn(value) == -1)
			warning |= NEGATIVE_SERIAL_NUMBER_WARNING;
		};

issuer @after{#ifdef DEBUG
	pop_rule(); 
	#endif}	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		notEmptyName{cert->issuer = dname;};

subject @after{#ifdef DEBUG
	pop_rule(); 
	#endif}	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		notEmptyName {cert->subject = dname;};

validity @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag time1=time_span time2=time_span {cert->validity = malloc(sizeof(X509_VAL));
		cert->validity->notBefore = $time1.text;
		cert->validity->notAfter = $time2.text;
	};
	
subjectPKinfo @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag {cert->pkey = malloc(sizeof(PUBKEY_ALG));} (rsapk | dsapk | dhpk | ecpk | keapk |rsapsspk | rsaoaep | gostpk); //public key

rsapk @after{#ifdef DEBUG
	pop_rule(); 
	#endif}	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		rsa_alg_id constructedBitString sequenceTag n=integer e=integer {
	new_rsa_pk($n.text,$e.text);
	cert->mask = 15;cert->mask_ca=9;};

dsapk @after{#ifdef DEBUG
	pop_rule(); 
	#endif}	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		dsa_alg_id constructedBitString integer {
	cert->pkey->pubkey = malloc(sizeof(PUBKEY));
	cert->pkey->pubkey->dsa_dh_key = $integer.text;
	cert->mask = 63;cert->mask_ca=57;};

dhpk @after{#ifdef DEBUG
	pop_rule(); 
	#endif}	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		dh_alg_id bitstring {
	cert->pkey->pubkey = malloc(sizeof(PUBKEY));
	if($bitstring.text->data[0] != 2)
	{
		printf("Error! Not integer in diffie hellman public key \n");
		exit(DH_KEY_NOT_INTEGER_ERROR);	
	}	
	mpz_t length;
	mpz_init_set_ui(length,0);
	int len = compute_len($bitstring.text->data,length);
	cert->pkey->pubkey->dsa_dh_key = new_asn1_string(2,mpz_get_ui(length),$bitstring.text->data+len);
	cert->mask = 246;cert->mask_ca=246;}; //there is an integer in the value field

keapk @after{#ifdef DEBUG
	pop_rule(); 
	#endif}	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		kea_alg_id bitstring {
	new_bitstring_pk($bitstring.text);
	cert->mask = 246;cert->mask_ca=246;};

ecpk @after{#ifdef DEBUG
	pop_rule(); 
	#endif}	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		ec_alg_id bitstring {new_bitstring_pk($bitstring.text);}
	;
	
gostpk @after{#ifdef DEBUG
	pop_rule(); 
	#endif}	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag (gost94pkoid | gost01pkoid) (null | sequenceTag oid oid oid?)? constructedBitString octetstring 
		{cert->pkey->pubkey = malloc(sizeof(PUBKEY));cert->pkey->pubkey->gost_key = $octetstring.text;cert->mask = 22;cert->mask_ca=57;};
	
rsapsspk @after{#ifdef DEBUG
	pop_rule(); 
	#endif}	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		pss_alg_id constructedBitString sequenceTag n=integer e=integer {
	new_rsa_pk($n.text,$e.text);
	cert->mask = 63;cert->mask_ca=57;};

rsaoaep @after{#ifdef DEBUG
	pop_rule(); 
	#endif}	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		oaep_alg_id constructedBitString sequenceTag n=integer e=integer {
	new_rsa_pk($n.text,$e.text);
	cert->mask = 159;cert->mask_ca=159;};

subjectuniqueId @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		tag2{
		ASN1_STRING *bs;
		bs = malloc(sizeof(ASN1_STRING));
		compute_bitstring ($tag2.text->value,$tag2.text->length,bs);	
	};
	
issueruniqueId @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		tag1 {
		ASN1_STRING *bs;
		bs = malloc(sizeof(ASN1_STRING));
		compute_bitstring ($tag1.text->value,$tag1.text->length,bs);	
	};


extensionsWithSubAlt @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	@init{if(cert->extensions == NULL)
		cert->extensions = sk_x509_EXTENSION_new_null();
	#ifdef DEBUG 
	push_rule(__func__); 
	#endif
	}
	:	extensionNoSubAlt extensionsWithSubAlt
	|	basicConstraintsNotCritical ( truevalue {bc_ext->critical=1;} constructedOctetString sequenceTag ( falsevalue? notDependentExtsSubAlt | truevalue {bc_ext->value->basic_constraints->is_ca = 1;} ( extensionsNotBCSubAlt | integer {bc_ext->value->basic_constraints->pathlen=$integer.text;} extensionsCertSignAndSkiSubAlt)) 
				|falsevalue? constructedOctetString sequenceTag ( falsevalue? notDependentExtsSubAlt | truevalue {bc_ext->value->basic_constraints->is_ca = 1;} extensionsNotCertSignAndSkiSubAlt ) )
	|	keyUsageCommon (bitstring {key_usage_ext->value->keyusage = $bitstring.text;} extensionsNoPathLenSubAlt | bitstringCertSign extensionsMustBeCAandSkiSubAlt)
	|	dependentExtension extensionsMustBeCaAndSkiSubAlt
	|	subjectKeyId extensionsNoSkiSubAlt
	|	subAltNameCritical extensions
	;

extensionsNoSkiSubAlt 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:
		extensionNoSubAlt extensionsNoSkiSubAlt
	|	basicConstraintsNotCritical ( truevalue {bc_ext->critical=1;} constructedOctetString sequenceTag ( falsevalue? notDependentExtsSubAlt | truevalue {bc_ext->value->basic_constraints->is_ca = 1;} ( extensionsNotBCNotSkiSubAlt | integer {bc_ext->value->basic_constraints->pathlen=$integer.text;} extensionsCertSignSubAlt)) 
				|falsevalue? constructedOctetString sequenceTag ( falsevalue? notDependentExtsSubAlt | truevalue {bc_ext->value->basic_constraints->is_ca = 1;} extensionsNotCertSignSubAlt ) )
	|	keyUsageCommon (bitstring {key_usage_ext->value->keyusage = $bitstring.text;} extensionsNoPathLenNoSkiSubAlt | bitstringCertSign extensionsMustBeCASubAlt)
	|	dependentExtension extensionsMustBeCaSubAlt
	|	subAltNameCritical ( |extensionsNoSki)
	;
	
extensions @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	@init{if(cert->extensions == NULL)
		cert->extensions = sk_x509_EXTENSION_new_null();
	#ifdef DEBUG 
	push_rule(__func__); 
	#endif	
	}
	:	extension ( |extensions)
	|	basicConstraintsNotCritical ( truevalue {bc_ext->critical=1;} constructedOctetString sequenceTag ( falsevalue? ( |notDependentExts) | truevalue {bc_ext->value->basic_constraints->is_ca = 1;} ( extensionsNotBC | integer {bc_ext->value->basic_constraints->pathlen=$integer.text;} extensionsCertSignAndSki)) 
				|falsevalue? constructedOctetString sequenceTag ( falsevalue? ( |notDependentExts) | truevalue {bc_ext->value->basic_constraints->is_ca = 1;} extensionsNotCertSignAndSki ) )
	|	keyUsageCommon (bitstring {key_usage_ext->value->keyusage = $bitstring.text;} ( |extensionsNoPathLen) | bitstringCertSign extensionsMustBeCAandSki)
	|	dependentExtension extensionsMustBeCaAndSki
	|	subjectKeyId extensionsNoSki?
	;
	
extensionsNoSki 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}:
		extension ( |extensionsNoSki)
	|	basicConstraintsNotCritical ( truevalue {bc_ext->critical=1;} constructedOctetString sequenceTag ( falsevalue? ( |notDependentExts) | truevalue {bc_ext->value->basic_constraints->is_ca = 1;} ( extensionsNotBCNotSki? | integer {bc_ext->value->basic_constraints->pathlen=$integer.text;} extensionsCertSign)) 
				|falsevalue? constructedOctetString sequenceTag ( falsevalue? ( |notDependentExts) | truevalue {bc_ext->value->basic_constraints->is_ca = 1;} extensionsNotCertSign? ) )
	|	keyUsageCommon (bitstring {key_usage_ext->value->keyusage = $bitstring.text;} ( |extensionsNoPathLenNoSki) | bitstringCertSign extensionsMustBeCA)
	|	dependentExtension extensionsMustBeCa
	;
	
extensionsNoPathLenSubAlt 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:
		extensionNoSubAlt extensionsNoPathLenSubAlt
	|	basicConstraints ( falsevalue? notDependentExtsSubAlt | truevalue {bc_ext->value->basic_constraints->is_ca = 1;} extensionsNotBCNotKeyUsageSubAlt )
	|	dependentExtension extensionsMustBeCaAndSkiNoPathLenSubAlt
	|	subjectKeyId extensionsNoPathLenNoSkiSubAlt
	|	subAltNameCritical ( |extensionsNoPathLen)
	;	


extensionsNoPathLen 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:
		extension ( |extensionsNoPathLen)
	|	basicConstraints ( falsevalue? ( |notDependentExts) | truevalue {bc_ext->value->basic_constraints->is_ca = 1;} extensionsNotBCNotKeyUsage )
	|	dependentExtension extensionsMustBeCaAndSkiNoPathLen
	|	subjectKeyId ( |extensionsNoPathLenNoSki)
	;	
	
extensionsNoPathLenNoSkiSubAlt 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}:
		extensionNoSubAlt extensionsNoPathLenNoSkiSubAlt
	|	basicConstraints ( falsevalue? notDependentExtsSubAlt | truevalue {bc_ext->value->basic_constraints->is_ca = 1;} extensionsNotBCNotKeyUsageNotSkiSubAlt )
	|	dependentExtension extensionsMustBeCaNoPathLenSubAlt
	|	subAltNameCritical ( |extensionsNoPathLenNoSki)
	;
	
extensionsNoPathLenNoSki 	
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}:
		extension ( |extensionsNoPathLenNoSki)
	|	basicConstraints ( falsevalue? ( |notDependentExts) | truevalue {bc_ext->value->basic_constraints->is_ca = 1;} ( |extensionsNotBCNotKeyUsageNotSki) )
	|	dependentExtension extensionsMustBeCaNoPathLen
	;

notDependentExtsSubAlt 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}:
		(extensionNoSubAlt | keyUsage | subjectKeyId) notDependentExtsSubAlt
	|	subAltNameCritical ( |notDependentExts);
	
notDependentExts 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}:
		(extension | keyUsage | subjectKeyId) ( |notDependentExts);

extensionsCertSignSubAlt 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:
		extensionNoSubAlt extensionsCertSignSubAlt
	|	dependentExtension extensionsCertSignSubAlt
	|	keyUsageCommon bitstringCertSign extensionsNotBCNotKeyUsageNotSkiSubAlt
	|	subAltNameCritical extensionsCertSign;
	
extensionsCertSign 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:
		extension extensionsCertSign
	|	dependentExtension extensionsCertSign
	|	keyUsageCommon bitstringCertSign extensionsNotBCNotKeyUsageNotSki?;
	
extensionsCertSignAndSkiSubAlt 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:
		extensionNoSubAlt extensionsCertSignAndSkiSubAlt
	|	dependentExtension extensionsCertSignAndSkiSubAlt
	|	keyUsageCommon bitstringCertSign extensionsNotBCNotKeyUsage
	|	subjectKeyId extensionsCertSignSubAlt
	|	subAltNameCritical extensionsCertSignAndSki
	;


extensionsCertSignAndSki 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}:
		extension extensionsCertSignAndSki
	|	dependentExtension extensionsCertSignAndSki
	|	keyUsageCommon bitstringCertSign extensionsNotBCNotKeyUsage
	|	subjectKeyId extensionsCertSign
	;
extensionsNotCertSignSubAlt 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}:
		extensionNoSubAlt extensionsNotCertSignSubAlt
	|	dependentExtension extensionsNotCertSignSubAlt
	|	keyUsageCommon bitstring {key_usage_ext->value->keyusage = $bitstring.text;} extensionsNotBCNotKeyUsageNotSkiSubAlt
	|	subAltNameCritical extensionsNotCertSign;	

extensionsNotCertSign 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:
		extension ( |extensionsNotCertSign)
	|	dependentExtension ( |extensionsNotCertSign)
	|	keyUsageCommon bitstring {key_usage_ext->value->keyusage = $bitstring.text;} extensionsNotBCNotKeyUsageNotSki?;

extensionsNotCertSignAndSkiSubAlt 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:
		extensionNoSubAlt extensionsNotCertSignAndSkiSubAlt
	|	dependentExtension extensionsNotCertSignAndSkiSubAlt
	|	keyUsageCommon bitstring {key_usage_ext->value->keyusage = $bitstring.text;} extensionsNotBCNotKeyUsageSubAlt
	|	subjectKeyId extensionsNotCertSignSubAlt
	|	subAltNameCritical extensionsNotCertSignAndSki ;

extensionsNotCertSignAndSki 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif} 
	:
		extension extensionsNotCertSignAndSki
	|	dependentExtension extensionsNotCertSignAndSki
	|	keyUsageCommon bitstring {key_usage_ext->value->keyusage = $bitstring.text;} extensionsNotBCNotKeyUsage
	|	subjectKeyId extensionsNotCertSign?;
	
extension @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		{printf("It's ext \n");}sequenceTag  (authKeyId  | certPolicies | subAltName | issuerAltName | subDirAttr| extendKeyUsage | crldp | sia | aia | freshcrl | genericExt );
	
extensionNoSubAlt @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		{printf("It's ext \n");}sequenceTag  (authKeyId  | certPolicies | issuerAltName | subDirAttr| extendKeyUsage | crldp | sia | aia | freshcrl | genericExt );

	
genericExt 	@init{x509_EXTENSION *ext=malloc(sizeof(x509_EXTENSION));}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		oid {
	printf("It's genericext \n");
	mpz_t index;
	mpz_init(index);
	compute_index($oid.text->oid,$oid.text->len,index);
	insert_extension(index);
	ext->oid=$oid.text->obj;
	ext->critical=0;
	ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
	}
	(critical {ext->critical=$critical.bool;})? octetstring {ext->value->octet=$octetstring.text;
	sk_x509_EXTENSION_push(cert->extensions,ext);
	};
	
authKeyId @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	@init{AUTH_KEY_ID *aki;}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		akioid falsevalue? constructedOctetString sequenceTag { 
		aki=malloc(sizeof(AUTH_KEY_ID));aki->key_id=NULL;aki->auth_cert_issuer=NULL;aki->cert_serial_number=NULL;} 
		(tag0 {aki->key_id=(ASN1_OCTET_STRING *) new_asn1_string(4,$tag0.text->length,$tag0.text->value);cert->key_id=1;})? 
		(constructedTag1 generalNames {aki->auth_cert_issuer=$generalNames.text;})? 
		(tag2{aki->cert_serial_number=(ASN1_INTEGER *) new_asn1_string(2,$tag2.text->length,$tag2.text->value);})?
		{
		x509_EXTENSION *ext = malloc(sizeof(x509_EXTENSION));
		ext->oid = $akioid.obj;
		ext->critical = 0;
		ext->value = malloc(sizeof(X509_EXTENSION_VALUE));
		ext->value->aki=aki;
		sk_x509_EXTENSION_push(cert->extensions,ext);
		};
	
subjectKeyId @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag skioid falsevalue? constructedOctetString octetstring{x509_EXTENSION *ext = malloc(sizeof(x509_EXTENSION));
		ext->oid = $skioid.obj;
		ext->critical = 0;
		ext->value = malloc(sizeof(X509_EXTENSION_VALUE));
		ext->value->octet=$octetstring.text;
		sk_x509_EXTENSION_push(cert->extensions,ext);};
	
keyUsage @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag keyusageoid {key_usage_ext=malloc(sizeof(x509_EXTENSION));key_usage_ext->oid=$keyusageoid.obj;key_usage_ext->critical=0;key_usage_ext->value=malloc(sizeof(X509_EXTENSION_VALUE));}
		(critical {key_usage_ext->critical=$critical.bool;})? constructedOctetString bitstring {key_usage_ext->value->keyusage = $bitstring.text;};
	
keyUsageCommon @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag keyusageoid {key_usage_ext=malloc(sizeof(x509_EXTENSION));key_usage_ext->oid=$keyusageoid.obj;key_usage_ext->critical=0;
		key_usage_ext->value=malloc(sizeof(X509_EXTENSION_VALUE));key_usage_ext->value->keyusage=NULL;} 
		(critical {key_usage_ext->critical=$critical.bool;})? constructedOctetString;
	
certPolicies @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	@init{x509_EXTENSION *ext = malloc(sizeof(x509_EXTENSION));}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		certpolioid {ext->oid=$certpolioid.obj;ext->critical=0;} 
		(critical{ext->critical=$critical.bool;})? 
		constructedOctetString sequenceTag policies {ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
		ext->value->policies = $policies.text;
		sk_x509_EXTENSION_push(cert->extensions,ext);};
	
policies returns[STACK_OF(POLICY_INFO) *text] @init{$text=sk_POLICY_INFO_new_null();}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		(policyInfo {sk_POLICY_INFO_push($text,$policyInfo.text);})+;
	
policyInfo returns [POLICY_INFO *text]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag {sequence_pointer = counter_list;$text=malloc(sizeof(POLICY_INFO));} (oid {$text->oid=$oid.text->obj;$text->qualifiers=NULL;
	mpz_t index;
	mpz_init(index);
	compute_index($oid.text->oid,$oid.text->len,index);
	insert_policy(index);	
	}(sequenceTag policyQualifiers {$text->qualifiers=$policyQualifiers.text;})?
	|anypolicyoid {$text->oid=$anypolicyoid.obj;$text->qualifiers=NULL;
	mpz_t index;
	mpz_init_set_ui(index,2058699496953);
	insert_policy(index);
	}(sequenceTag policyQualifiersAnyPolicy {$text->qualifiers=$policyQualifiersAnyPolicy.text;})?)
		;

policyQualifiers returns[STACK_OF(POLICY_QUALIFIER) *text]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		{$text=sk_POLICY_QUALIFIER_new_null();}(qualifier{sk_POLICY_QUALIFIER_push($text,$qualifier.text);})+ ;

qualifier returns[POLICY_QUALIFIER *text]
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:
	{sequence_pointer != NULL}?=>
		 ( sequenceTag {$text=malloc(sizeof(POLICY_QUALIFIER));$text->qualifier=malloc(sizeof(QUALIFIER));} 
		(cps {$text->oid=OBJ_nid2obj(NID_id_qt_cps);$text->qualifier->cps=$cps.text;} | unotice {$text->oid=OBJ_nid2obj(NID_id_qt_unotice);$text->qualifier->unotice=$unotice.text;}
		| oid any {$text->oid=$oid.text->obj;$text->qualifier->any=$any.text;}));
		
policyQualifiersAnyPolicy returns[STACK_OF(POLICY_QUALIFIER) *text]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		{$text=sk_POLICY_QUALIFIER_new_null();}(qualifierAnyPolicy{sk_POLICY_QUALIFIER_push($text,$qualifierAnyPolicy.text);})+ ;

qualifierAnyPolicy returns[POLICY_QUALIFIER *text]
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:
	{sequence_pointer != NULL}?=>
		 ( sequenceTag {$text=malloc(sizeof(POLICY_QUALIFIER));$text->qualifier=malloc(sizeof(QUALIFIER));} 
		(cps {$text->oid=OBJ_nid2obj(NID_id_qt_cps);$text->qualifier->cps=$cps.text;} | unotice {$text->oid=OBJ_nid2obj(NID_id_qt_unotice);$text->qualifier->unotice=$unotice.text;}
		));

cps returns[ASN1_IA5STRING *text]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	cpsoid ia5String{$text=$ia5String.text;}; //it should be ia5string

unotice  returns[USERNOTICE *text]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		unoticeoid sequenceTag {$text=malloc(sizeof(USERNOTICE));$text->noticeref=NULL;$text->exptext=NULL;} 
		(noticeref {$text->noticeref=$noticeref.text;})? (displayTextString{$text->exptext=$displayTextString.text;})?;
	
displayTextString returns[ASN1_STRING *text] 
@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
@init{unsigned long mask;
	#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	:
		(ia5String {$ia5String.text->type=MBSTRING_ASC;mask=B_ASN1_IA5STRING;$text=$ia5String.text;}
	|	visibleString {$visibleString.text->type=MBSTRING_ASC;mask=B_ASN1_VISIBLESTRING;$text=$visibleString.text;}
	|	bmpString {$bmpString.text->type=MBSTRING_BMP;mask=B_ASN1_BMPSTRING;$text=$bmpString.text;}
	|	utf8String {$utf8String.text->type=MBSTRING_UTF8;mask=B_ASN1_UTF8STRING;$text=$utf8String.text;})
	{
	ASN1_STRING *out = malloc(sizeof(ASN1_STRING));
	out->data = NULL;
	if(ASN1_mbstring_ncopy(&out,$text->data,$text->length,$text->type,mask,1,200) == -1)
	{
		printf("Display Text String length constraint not satisfied \n");
		warning|=DISPLAY_STRING_LENGTH_WARNING;
	}	
	free($text);
	$text=out;
	}
	;	
		
noticeref returns[NOTICEREF *text]
@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
		:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag displayTextString sequenceTag noticeNumbers {$text=malloc(sizeof(NOTICEREF));$text->organization=$displayTextString.text;$text->noticenos=$noticeNumbers.text;};
	
noticeNumbers returns[STACK_OF(ASN1_INTEGER) *text] @init{$text=NULL;}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		(integer{
	if($text == NULL)
		$text= sk_ASN1_INTEGER_new_null();
	sk_ASN1_INTEGER_push($text,$integer.text);
	})*;
	

subAltName @init{x509_EXTENSION *ext = malloc(sizeof(x509_EXTENSION));}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	subaltoid {ext->oid=$subaltoid.obj;ext->critical=0;}(critical {ext->critical=$critical.bool;})? 
	constructedOctetString sequenceTag generalNames {ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
	ext->value->gen_names=$generalNames.text;
	sk_x509_EXTENSION_push(cert->extensions,ext);};
	

subAltNameCritical 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag subaltoid truevalue constructedOctetString sequenceTag generalNames {x509_EXTENSION *ext = malloc(sizeof(x509_EXTENSION));
		ext->oid = $subaltoid.obj;
		ext->critical = 1;
		ext->value = malloc(sizeof(X509_EXTENSION_VALUE));
		ext->value->gen_names=$generalNames.text;
		sk_x509_EXTENSION_push(cert->extensions,ext);};	

issuerAltName @init{x509_EXTENSION *ext = malloc(sizeof(x509_EXTENSION));}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		issaltoid {ext->oid=$issaltoid.obj;ext->critical=0;}(critical {ext->critical=$critical.bool;})? 
	constructedOctetString sequenceTag generalNames {ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
	ext->value->gen_names=$generalNames.text;
	sk_x509_EXTENSION_push(cert->extensions,ext);};
	
subDirAttr @init{x509_EXTENSION *ext = malloc(sizeof(x509_EXTENSION));}	
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		subdiroid {ext->oid=$subdiroid.obj;ext->critical=0;} (critical{ext->critical=$critical.bool;})? constructedOctetString sequenceTag {sequence_pointer=counter_list;}
		 attributes{
	ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
	ext->value->subject_directory=$attributes.text;
	sk_x509_EXTENSION_push(cert->extensions,ext);};

attributes returns[STACK_OF(SUBJECT_DIRECTORY_ATTRIBUTES) *text]  @init{$text=sk_SUBJECT_DIRECTORY_ATTRIBUTES_new_null();}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		(attribute {sk_SUBJECT_DIRECTORY_ATTRIBUTES_push($text,$attribute.text);})+;
	
attribute returns[SUBJECT_DIRECTORY_ATTRIBUTES *text]   @init{$text=malloc(sizeof(SUBJECT_DIRECTORY_ATTRIBUTES));#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:
	{sequence_pointer != NULL}?=>	sequenceTag( (cnoid {$text->oid=$cnoid.obj;} | oidon {$text->oid=$oidon.obj;}| oidname {$text->oid=$oidname.obj;}| surnameoid {$text->oid=$surnameoid.obj;}| givenoid {$text->oid=$givenoid.obj;}
	| initoid {$text->oid=$initoid.obj;}| genqualifieroid {$text->oid=$genqualifieroid.obj;}| localoid {$text->oid=$localoid.obj;}| ouoid {$text->oid=$ouoid.obj;}
	| sorpoid {$text->oid=$sorpoid.obj;} |titleoid {$text->oid=$titleoid.obj;}| pseudooid {$text->oid=$pseudooid.obj;}) {$text->value=malloc(sizeof(SUB_DIR_ATTRS_VALUE));
	$text->value->str_value = sk_STRING_POINTER_new_null();} 
	set (directoryString
	{
	ASN1_STRING *out = malloc(sizeof(ASN1_STRING));
	out->data = NULL;
	ASN1_STRING_TABLE *tbl = ASN1_STRING_TABLE_get(OBJ_obj2nid($text->oid));
	if(ASN1_mbstring_ncopy(&out,$directoryString.text->data,$directoryString.text->length,$directoryString.text->type,tbl->mask,tbl->minsize,tbl->maxsize) == -1)
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}	
	sk_STRING_POINTER_push($text->value->str_value,out);
	})+ 
	|oid any {$text->oid=$oid.text->obj;$text->value=malloc(sizeof(SUB_DIR_ATTRS_VALUE));$text->value->any_value=$any.text;}
	|	(dnoid {$text->oid=$dnoid.obj;} | countryoid {$text->oid=$countryoid.obj;}| serialoid {$text->oid=$serialoid.obj;}) {$text->value=malloc(sizeof(SUB_DIR_ATTRS_VALUE));
	$text->value->str_value = sk_STRING_POINTER_new_null();} 
	set (printString 
	{
	ASN1_STRING *out = malloc(sizeof(ASN1_STRING));
	out->data = NULL;
	ASN1_STRING_TABLE *tbl = ASN1_STRING_TABLE_get(OBJ_obj2nid($text->oid));
	if(ASN1_mbstring_ncopy(&out,$printString.text->data,$printString.text->length,MBSTRING_ASC,tbl->mask,tbl->minsize,tbl->maxsize) == -1)
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	sk_STRING_POINTER_push($text->value->str_value,out);
	})+
	);
	
basicConstraints 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag bcoid {bc_ext = malloc(sizeof(x509_EXTENSION));bc_ext->oid=$bcoid.obj;bc_ext->critical=0;bc_ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
		bc_ext->value->basic_constraints=malloc(sizeof(BASIC_CONSTRAINT));bc_ext->value->basic_constraints->is_ca=0;bc_ext->value->basic_constraints->pathlen=NULL;}
		(critical {bc_ext->critical=$critical.bool;})? constructedOctetString sequenceTag;
	
basicConstraintsNotCritical 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag bcoid {bc_ext = malloc(sizeof(x509_EXTENSION));bc_ext->oid=$bcoid.obj;bc_ext->critical=0;bc_ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
		bc_ext->value->basic_constraints=malloc(sizeof(BASIC_CONSTRAINT));bc_ext->value->basic_constraints->is_ca=0;bc_ext->value->basic_constraints->pathlen=NULL;};
	
extendKeyUsage @init{x509_EXTENSION *ext = malloc(sizeof(x509_EXTENSION));}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		ekuoid {ext->oid=$ekuoid.obj;ext->critical=0;} (critical{ext->critical=$critical.bool;})? constructedOctetString sequenceTag usages
	{ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
	ext->value->ext_key_usage=$usages.text;
	sk_x509_EXTENSION_push(cert->extensions,ext);
	}
	;
	
usages returns[EXTENDED_KEY_USAGE *text] @init{$text = sk_ASN1_OBJECT_new_null();}	
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		(usage {sk_ASN1_OBJECT_push($text,$usage.obj);})+;

usage returns[ASN1_OBJECT *obj]
 	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif
	}
 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:
		oid {$obj=$oid.text->obj;cert->eku_mask &=255;} | serverauthoid {$obj=$serverauthoid.obj;cert->eku_mask &=168;} 
		| clientauthoid {$obj=$clientauthoid.obj;cert->eku_mask &=136;}| codesignoid {$obj=$codesignoid.obj;cert->eku_mask &=128;}
		| emailprotectoid {$obj=$emailprotectoid.obj;cert->eku_mask &=232;}| timestampoid {$obj=$timestampoid.obj;cert->eku_mask &=192;}
		| ocspsignoid {$obj=$ocspsignoid.obj;cert->eku_mask &=192;}| anyusageoid {$obj=$anyusageoid.obj;eku_mask=255;};

crldp @init{x509_EXTENSION *ext = malloc(sizeof(x509_EXTENSION));}	
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		crldpoid {ext->oid=$crldpoid.obj;ext->critical=0;ext->value=malloc(sizeof(X509_EXTENSION_VALUE));}(critical{ext->critical=$critical.bool;})? 
		constructedOctetString sequenceTag dps {ext->value->crl_dps=$dps.text;sk_x509_EXTENSION_push(cert->extensions,ext);};

dps returns[STACK_OF(CRL_DISTRIBUTION_POINT) *text]	@init{$text = sk_CRL_DISTRIBUTION_POINT_new_null();}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		(dp {sk_CRL_DISTRIBUTION_POINT_push($text,$dp.text);})+;

dp returns [CRL_DISTRIBUTION_POINT *text] @init{$text = malloc(sizeof(CRL_DISTRIBUTION_POINT));$text->dp_name=NULL;$text->reason_flags=NULL;$text->crl_issuer=NULL;} 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag (constructedTag0 {$text->dp_name=malloc(sizeof(DP_NAME));}(constructedTag0 fn=generalNames {$text->dp_name->full_name=$fn.text;}
		(t1=tag1{$text->reason_flags=new_asn1_string(3,$t1.text->length,$t1.text->value);})? (constructedTag2 gn=generalNames {$text->crl_issuer = $gn.text;})?
		|constructedTag1 {dname=sk_X509_DNAME_ENTRY_new_null();}rdn {$text->dp_name->relative_to_crl_issuer=dname;}
		(t1=tag1{$text->reason_flags=new_asn1_string(3,$t1.text->length,$t1.text->value);})? 
		(constructedTag2 generalName {STACK_OF(GENERAL_NAME_POINTER) *gn=sk_GENERAL_NAME_POINTER_new_null();sk_GENERAL_NAME_POINTER_push(gn,gen_name);$text->crl_issuer = gn;})?) 
		|(t1=tag1 {$text->reason_flags=new_asn1_string(3,$t1.text->length,$t1.text->value);})? constructedTag2 gn=generalNames {$text->crl_issuer = $gn.text;});

/*dpname returns[DP_NAME *text] @init{$text = malloc(sizeof(DP_NAME));#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:
		(constructedTag0 generalNames {$text->full_name=$generalNames.text;} | constructedTag1 {dname=sk_X509_DNAME_ENTRY_new_null();}rdn {$text->relative_to_crl_issuer=dname;});
*/
freshcrl	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		freshcrloid falsevalue? constructedOctetString sequenceTag dps {x509_EXTENSION *ext = malloc(sizeof(x509_EXTENSION));
	ext->oid=$freshcrloid.obj;
	ext->critical=0;
	ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
	ext->value->crl_dps=$dps.text;
	sk_x509_EXTENSION_push(cert->extensions,ext);
	};

aia @init{x509_EXTENSION *ext = malloc(sizeof(x509_EXTENSION));}	
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		aiaoid falsevalue? constructedOctetString sequenceTag ads{
	ext->oid=$aiaoid.obj;
	ext->critical=0;
	ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
	ext->value->access_descriptions=$ads.text;
	sk_x509_EXTENSION_push(cert->extensions,ext);
	};

ads returns[STACK_OF(ACCESS_DESCRIPTIONS) *text] @init{$text = sk_ACCESS_DESCRIPTIONS_new_null();}	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	(ad {sk_ACCESS_DESCRIPTIONS_push($text,$ad.text);})+;

ad returns[ACCESS_DESCRIPTIONS *text] @init{$text = malloc(sizeof(ACCESS_DESCRIPTIONS));}	
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag (caissueroid generalName {$text->access_method=$caissueroid.obj;}
	| ocspoid generalName {$text->access_method=$ocspoid.obj;}| oid generalName {$text->access_method=$oid.text->obj;}) {$text->access_location=gen_name;}
	;

sia @init{x509_EXTENSION *ext = malloc(sizeof(x509_EXTENSION));}	
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		siaoid falsevalue? constructedOctetString sequenceTag siaads{
	ext->oid=$siaoid.obj;
	ext->critical=0;
	ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
	ext->value->access_descriptions=$siaads.text;
	sk_x509_EXTENSION_push(cert->extensions,ext);
	};

siaads returns[STACK_OF(ACCESS_DESCRIPTIONS) *text] @init{$text = sk_ACCESS_DESCRIPTIONS_new_null();}	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	(adsia {sk_ACCESS_DESCRIPTIONS_push($text,$adsia.text);})+;

adsia returns[ACCESS_DESCRIPTIONS *text] @init{$text = malloc(sizeof(ACCESS_DESCRIPTIONS));}	
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag (carepooid generalName {$text->access_method=$carepooid.obj;ca_repo=1;}
	| tspoid generalName {$text->access_method=$tspoid.obj;tsp=1;}| oid generalName {$text->access_method=$oid.text->obj;}) {$text->access_location=gen_name;}
	;
			
dependentExtension 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		{printf("dependent parsed \n");} sequenceTag (policyMappings | nameConstraints | policyConstraints | inhibitAnyPolicy);

inhibitAnyPolicy
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		inhibitanyoid truevalue constructedOctetString integer{x509_EXTENSION *ext = malloc(sizeof(x509_EXTENSION));
	ext->oid=$inhibitanyoid.obj;
	ext->critical=1;
	ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
	ext->value->inhibit_any_policy=$integer.text;
	sk_x509_EXTENSION_push(cert->extensions,ext);
	};

policyConstraints @init{x509_EXTENSION *ext = malloc(sizeof(x509_EXTENSION));}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		polconstraintsoid truevalue constructedOctetString sequenceTag {ext->oid=$polconstraintsoid.obj;ext->critical=1;
	ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
	ext->value->policy_constraints=malloc(sizeof(POLICY_CONSTRAINTS));
	ext->value->policy_constraints->requireExplicitPolicy=NULL;
	ext->value->policy_constraints->inhibitPolicyMapping=NULL;
	//fprintf(stdout,"\%x \n",ext->value->policy_constraints);
	}(tag0 {ext->value->policy_constraints->requireExplicitPolicy=new_asn1_string(2,$tag0.text->length,$tag0.text->value);}(t1=tag1{
	ext->value->policy_constraints->inhibitPolicyMapping=new_asn1_string(2,$t1.text->length,$t1.text->value);
	})? | t1=tag1 {ext->value->policy_constraints->inhibitPolicyMapping=new_asn1_string(2,$t1.text->length,$t1.text->value);})
	{sk_x509_EXTENSION_push(cert->extensions,ext);};
	

nameConstraints @init{x509_EXTENSION *ext = malloc(sizeof(x509_EXTENSION));}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	 nameoid truevalue constructedOctetString sequenceTag {
	ext->oid=$nameoid.obj;ext->critical=1;ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
	ext->value->name_constraints=malloc(sizeof(NAME_CONSTRAINT ));
	} (constructedTag0 tree0=generalSubtrees {ext->value->name_constraints->permitted_subtrees=$tree0.text;
	ext->value->name_constraints->excluded_subtrees=NULL;
	}(constructedTag1 tree1=generalSubtrees {
	ext->value->name_constraints->excluded_subtrees=$tree1.text;
	})? | constructedTag1 tree1=generalSubtrees{ext->value->name_constraints->permitted_subtrees=NULL;
	ext->value->name_constraints->excluded_subtrees=$tree1.text;
	}) {sk_x509_EXTENSION_push(cert->extensions,ext);};
	
generalSubtrees returns[STACK_OF(GENERAL_SUBTREES) *text] @init{$text=sk_GENERAL_SUBTREES_new_null();}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		(subtree {sk_GENERAL_SUBTREES_push($text,$subtree.text);})+;
	
subtree returns[GENERAL_SUBTREES *text]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		sequenceTag generalName {$text=malloc(sizeof(GENERAL_SUBTREES));
	$text->gen_name=gen_name;
	$text->min_base_distance=new_asn1_string(2,1,min_base_distance);
	$text->max_base_distance=NULL;
	}(tag0{$text->min_base_distance=new_asn1_string(2,$tag0.text->length,$tag0.text->value);})? (tag1{$text->max_base_distance=new_asn1_string(2,$tag1.text->length,$tag1.text->value);})?;	

policyMappings  @init{x509_EXTENSION *ext = malloc(sizeof(x509_EXTENSION));}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	polmapoid {ext->oid=$polmapoid.obj;ext->critical=0;} (critical {ext->critical=$critical.bool;})? 
	constructedOctetString sequenceTag mappings {ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
	ext->value->mappings = $mappings.text;
	sk_x509_EXTENSION_push(cert->extensions,ext);};
	
mappings returns[POLICY_MAPPINGS *text] @init{$text=sk_x509_EXTENSION_new_null();}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		(sequenceTag iss=oid subj=oid {POLICY_MAPPING *map=malloc(sizeof(POLICY_MAPPING));
	map->issuerDomainPolicy=$iss.text->obj;
	map->subjectDomainPolicy=$subj.text->obj;
	sk_POLICY_MAPPING_push($text,map);})+;

basicConstraintsCA 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		{printf("BcCA parsed \n");}sequenceTag bcoid {bc_ext = malloc(sizeof(x509_EXTENSION));bc_ext->oid=$bcoid.obj;bc_ext->critical=0;bc_ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
		bc_ext->value->basic_constraints=malloc(sizeof(BASIC_CONSTRAINT));bc_ext->value->basic_constraints->is_ca=0;bc_ext->value->basic_constraints->pathlen=NULL;}
		(truevalue constructedOctetString sequenceTag truevalue {bc_ext->critical=1;bc_ext->value->basic_constraints->is_ca = 1;} ( extensionsNotBC |integer {bc_ext->value->basic_constraints->pathlen=$integer.text;} extensionsCertSignAndSki)
	|	falsevalue? constructedOctetString sequenceTag truevalue {bc_ext->value->basic_constraints->is_ca = 1;} extensionsNotCertSignAndSki)/*basic constrain extensions is CA*/;
	
basicConstraintsCANoSki 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		{printf("BcCA parsed \n");}sequenceTag bcoid {bc_ext = malloc(sizeof(x509_EXTENSION));bc_ext->oid=$bcoid.obj;bc_ext->critical=0;bc_ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
		bc_ext->value->basic_constraints=malloc(sizeof(BASIC_CONSTRAINT));bc_ext->value->basic_constraints->is_ca=0;bc_ext->value->basic_constraints->pathlen=NULL;}
		(truevalue constructedOctetString sequenceTag truevalue {bc_ext->critical=1;bc_ext->value->basic_constraints->is_ca = 1;} ( extensionsNotBCNotSki? |integer {bc_ext->value->basic_constraints->pathlen=$integer.text;} extensionsCertSign)
	|	falsevalue? constructedOctetString sequenceTag truevalue {bc_ext->value->basic_constraints->is_ca = 1;} extensionsNotCertSign?)/*basic constrain extensions is CA*/;
	

basicConstraintsCANoSkiSubAlt 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		{printf("BcCA parsed \n");}sequenceTag bcoid {bc_ext = malloc(sizeof(x509_EXTENSION));bc_ext->oid=$bcoid.obj;bc_ext->critical=0;bc_ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
		bc_ext->value->basic_constraints=malloc(sizeof(BASIC_CONSTRAINT));bc_ext->value->basic_constraints->is_ca=0;bc_ext->value->basic_constraints->pathlen=NULL;}
	(truevalue constructedOctetString sequenceTag truevalue {bc_ext->critical=1;bc_ext->value->basic_constraints->is_ca = 1;} ( extensionsNotBCNotSkiSubAlt |integer {bc_ext->value->basic_constraints->pathlen=$integer.text;} extensionsCertSignSubAlt)
	|	falsevalue? constructedOctetString sequenceTag truevalue {bc_ext->value->basic_constraints->is_ca = 1;} extensionsNotCertSignSubAlt)/*basic constrain extensions is CA*/;


basicConstraintsCASubAlt 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		{printf("BcCA parsed \n");}sequenceTag bcoid {bc_ext = malloc(sizeof(x509_EXTENSION));bc_ext->oid=$bcoid.obj;bc_ext->critical=0;bc_ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
		bc_ext->value->basic_constraints=malloc(sizeof(BASIC_CONSTRAINT));bc_ext->value->basic_constraints->is_ca=0;bc_ext->value->basic_constraints->pathlen=NULL;}
		(truevalue constructedOctetString sequenceTag truevalue {bc_ext->critical=1;bc_ext->value->basic_constraints->is_ca = 1;} ( extensionsNotBCSubAlt |integer  {bc_ext->value->basic_constraints->pathlen=$integer.text;} extensionsCertSignAndSkiSubAlt)
	|	falsevalue? constructedOctetString sequenceTag truevalue {bc_ext->value->basic_constraints->is_ca = 1;} extensionsNotCertSignAndSkiSubAlt)/*basic constrain extensions is CA*/;

extensionsMustBeCAandSkiSubAlt 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		(extensionsNotBCNotKeyUsageNotSkiNoSubAlt)? (sequenceTag bcoid truevalue {bc_ext = malloc(sizeof(x509_EXTENSION));bc_ext->oid=$bcoid.obj;bc_ext->critical=1;bc_ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
		bc_ext->value->basic_constraints=malloc(sizeof(BASIC_CONSTRAINT));bc_ext->value->basic_constraints->is_ca=0;bc_ext->value->basic_constraints->pathlen=NULL;}
	 constructedOctetString sequenceTag truevalue {bc_ext->value->basic_constraints->is_ca = 1;} (integer{bc_ext->value->basic_constraints->pathlen=$integer.text;})? extensionsNotBCNotKeyUsageSubAlt
	| subAltNameCritical extensionsMustBeCAandSki
	| subjectKeyId extensionsMustBeCASubAlt);		

	
extensionsMustBeCAandSki 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		(extensionsNotBCNotKeyUsageNotSki)? (sequenceTag bc=bcoid truevalue {bc_ext = malloc(sizeof(x509_EXTENSION));bc_ext->oid=$bc.obj;bc_ext->critical=1;bc_ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
		bc_ext->value->basic_constraints=malloc(sizeof(BASIC_CONSTRAINT));bc_ext->value->basic_constraints->is_ca=0;bc_ext->value->basic_constraints->pathlen=NULL;} 
	constructedOctetString sequenceTag truevalue {bc_ext->value->basic_constraints->is_ca = 1;} (i=integer{bc_ext->value->basic_constraints->pathlen=$i.text;})? extensionsNotBCNotKeyUsage
	| subjectKeyId (extensionsNotBCNotKeyUsageNotSki)? sequenceTag bc=bcoid truevalue {bc_ext = malloc(sizeof(x509_EXTENSION));bc_ext->oid=$bc.obj;bc_ext->critical=1;bc_ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
	bc_ext->value->basic_constraints=malloc(sizeof(BASIC_CONSTRAINT));bc_ext->value->basic_constraints->is_ca=0;bc_ext->value->basic_constraints->pathlen=NULL;}
	constructedOctetString sequenceTag truevalue {bc_ext->value->basic_constraints->is_ca = 1;} (i=integer{bc_ext->value->basic_constraints->pathlen=$i.text;})? (extensionsNotBCNotKeyUsageNotSki)?);		


extensionsMustBeCASubAlt
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	(extensionsNotBCNotKeyUsageNotSkiNoSubAlt)? (sequenceTag bc=bcoid truevalue {bc_ext = malloc(sizeof(x509_EXTENSION));bc_ext->oid=$bc.obj;bc_ext->critical=1;bc_ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
	bc_ext->value->basic_constraints=malloc(sizeof(BASIC_CONSTRAINT));bc_ext->value->basic_constraints->is_ca=0;bc_ext->value->basic_constraints->pathlen=NULL;}
	constructedOctetString sequenceTag truevalue {bc_ext->value->basic_constraints->is_ca = 1;} (i=integer{bc_ext->value->basic_constraints->pathlen=$i.text;})? extensionsNotBCNotKeyUsageNotSkiSubAlt
	| subAltNameCritical (extensionsNotBCNotKeyUsageNotSki)? sequenceTag bc=bcoid truevalue {bc_ext = malloc(sizeof(x509_EXTENSION));bc_ext->oid=$bc.obj;bc_ext->critical=1;bc_ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
	bc_ext->value->basic_constraints=malloc(sizeof(BASIC_CONSTRAINT));bc_ext->value->basic_constraints->is_ca=0;bc_ext->value->basic_constraints->pathlen=NULL;}
	constructedOctetString sequenceTag truevalue {bc_ext->value->basic_constraints->is_ca = 1;} (i=integer{bc_ext->value->basic_constraints->pathlen=$i.text;})?  (extensionsNotBCNotKeyUsageNotSki)?)

	;
	
extensionsMustBeCA
@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	(extensionsNotBCNotKeyUsageNotSki)? sequenceTag bcoid truevalue {bc_ext = malloc(sizeof(x509_EXTENSION));bc_ext->oid=$bcoid.obj;bc_ext->critical=1;bc_ext->value=malloc(sizeof(X509_EXTENSION_VALUE));
	bc_ext->value->basic_constraints=malloc(sizeof(BASIC_CONSTRAINT));bc_ext->value->basic_constraints->is_ca=0;bc_ext->value->basic_constraints->pathlen=NULL;}
	constructedOctetString sequenceTag truevalue {bc_ext->value->basic_constraints->is_ca = 1;} (integer{bc_ext->value->basic_constraints->pathlen=$integer.text;})? (extensionsNotBCNotKeyUsageNotSki)?

	;


extensionsMustBeCaAndSkiNoPathLenSubAlt 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:	(extensionsNotBCNotKeyUsageNotSkiNoSubAlt)? (basicConstraints truevalue {bc_ext->value->basic_constraints->is_ca = 1;} extensionsNotBCNotKeyUsageSubAlt
	| subAltNameCritical extensionsMustBeCaAndSkiNoPathLen
	| subjectKeyId extensionsMustBeCaNoPathLenSubAlt);

extensionsMustBeCaAndSkiNoPathLen 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:	(extensionsNotBCNotKeyUsageNotSki)? (basicConstraints truevalue {bc_ext->value->basic_constraints->is_ca = 1;} extensionsNotBCNotKeyUsage
	| subjectKeyId (extensionsNotBCNotKeyUsageNotSki)? basicConstraints truevalue {bc_ext->value->basic_constraints->is_ca = 1;} (extensionsNotBCNotKeyUsageNotSki)?);	


extensionsMustBeCaSubAlt 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:	extensionNoSubAlt extensionsMustBeCaSubAlt
	|	dependentExtension extensionsMustBeCaSubAlt
	|	keyUsageCommon (bitstring {key_usage_ext->value->keyusage = $bitstring.text;} extensionsMustBeCaNoPathLenSubAlt | bitstringCertSign extensionsMustBeCASubAlt)
	|	basicConstraintsCANoSkiSubAlt
	|	subAltNameCritical extensionsMustBeCa
	;

extensionsMustBeCa 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:	extension extensionsMustBeCa
	|	dependentExtension extensionsMustBeCa
	|	keyUsageCommon (bitstring {key_usage_ext->value->keyusage = $bitstring.text;} extensionsMustBeCaNoPathLen | bitstringCertSign extensionsMustBeCA)
	|	basicConstraintsCANoSki
	;
extensionsMustBeCaAndSkiSubAlt
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:	extensionNoSubAlt extensionsMustBeCaAndSkiSubAlt
	|	dependentExtension extensionsMustBeCaAndSkiSubAlt
	|	keyUsageCommon (bitstring {key_usage_ext->value->keyusage = $bitstring.text;} extensionsMustBeCaAndSkiNoPathLenSubAlt | bitstringCertSign extensionsMustBeCAandSkiSubAlt)
	|	basicConstraintsCASubAlt
	|	subjectKeyId extensionsMustBeCaSubAlt
	|	subAltNameCritical extensionsMustBeCaAndSki
	;
	
extensionsMustBeCaAndSki
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:	extension extensionsMustBeCaAndSki
	|	dependentExtension extensionsMustBeCaAndSki
	|	keyUsageCommon (bitstring {key_usage_ext->value->keyusage = $bitstring.text;} extensionsMustBeCaAndSkiNoPathLen | bitstringCertSign extensionsMustBeCAandSki)
	|	basicConstraintsCA
	|	subjectKeyId extensionsMustBeCa
	;
extensionsMustBeCaNoPathLenSubAlt 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:	extensionNoSubAlt extensionsMustBeCaNoPathLenSubAlt
	|	dependentExtension extensionsMustBeCaNoPathLenSubAlt
	|	basicConstraints truevalue {bc_ext->value->basic_constraints->is_ca = 1;} extensionsNotBCNotKeyUsageNotSkiSubAlt
	|	subAltNameCritical extensionsMustBeCaNoPathLen
	;
	
extensionsMustBeCaNoPathLen 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:	extension extensionsMustBeCaNoPathLen
	|	dependentExtension extensionsMustBeCaNoPathLen
	|	basicConstraints truevalue {bc_ext->value->basic_constraints->is_ca = 1;} (extensionsNotBCNotKeyUsageNotSki)?
	;


extensionsNotBCNotKeyUsageNotSkiSubAlt 	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:	
		extensionNoSubAlt extensionsNotBCNotKeyUsageNotSkiSubAlt
	|	dependentExtension extensionsNotBCNotKeyUsageNotSkiSubAlt	
	|	subAltNameCritical extensionsNotBCNotKeyUsageNotSki?;

extensionsNotBCNotKeyUsageNotSki 	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:	
		extension ( | extensionsNotBCNotKeyUsageNotSki)
	|	dependentExtension ( | extensionsNotBCNotKeyUsageNotSki)	;
	
extensionsNotBCNotKeyUsageNotSkiNoSubAlt 	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:	
		extensionNoSubAlt ( | extensionsNotBCNotKeyUsageNotSkiNoSubAlt)
	|	dependentExtension ( | extensionsNotBCNotKeyUsageNotSkiNoSubAlt)	;

extensionsNotBCNotKeyUsageSubAlt 	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:	
		extensionNoSubAlt extensionsNotBCNotKeyUsageSubAlt
	|	dependentExtension extensionsNotBCNotKeyUsageSubAlt	
	|	subjectKeyId extensionsNotBCNotKeyUsageNotSkiSubAlt
	|	subAltNameCritical extensionsNotBCNotKeyUsage;


extensionsNotBCNotKeyUsage 	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:	
		extension extensionsNotBCNotKeyUsage
	|	dependentExtension extensionsNotBCNotKeyUsage	
	|	subjectKeyId ( |extensionsNotBCNotKeyUsageNotSki);

extensionsNotBCSubAlt 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:	
		extensionNoSubAlt extensionsNotBCSubAlt
	|	dependentExtension extensionsNotBCSubAlt
	|	keyUsageCommon (bitstring {key_usage_ext->value->keyusage = $bitstring.text;} |bitstringCertSign) extensionsNotBCNotKeyUsageSubAlt
	|	subjectKeyId extensionsNotBCNotSkiSubAlt
	|	subAltNameCritical extensionsNotBC
	;

extensionsNotBC 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:	extension extensionsNotBC
	|	dependentExtension extensionsNotBC
	|	keyUsageCommon (bitstring {key_usage_ext->value->keyusage = $bitstring.text;} |bitstringCertSign) extensionsNotBCNotKeyUsage
	|	subjectKeyId ( |extensionsNotBCNotSki)
	;

extensionsNotBCNotSkiSubAlt 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:	extensionNoSubAlt extensionsNotBCNotSkiSubAlt
	|	dependentExtension extensionsNotBCNotSkiSubAlt
	|	keyUsageCommon (bitstring {key_usage_ext->value->keyusage = $bitstring.text;} |bitstringCertSign) extensionsNotBCNotKeyUsageNotSkiSubAlt
	|	subAltNameCritical ( |extensionsNotBCNotSki);
	
extensionsNotBCNotSki 
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:	extension ( | extensionsNotBCNotSki)
	|	dependentExtension ( | extensionsNotBCNotSki)
	|	keyUsageCommon (bitstring {key_usage_ext->value->keyusage = $bitstring.text;} |bitstringCertSign) ( |extensionsNotBCNotKeyUsageNotSki);
generalNames returns [STACK_OF(GENERAL_NAME_POINTER) *text]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	{general_name_pointer=counter_list;$text=sk_GENERAL_NAME_POINTER_new_null();}( {general_name_pointer != NULL}?=> generalName {sk_GENERAL_NAME_POINTER_push($text,gen_name);})+;

generalName @init{gen_name = malloc(sizeof(GEN_NAME));gen_name->name = malloc(sizeof(field_gen_name));
	#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:	constructedTag0 othername {gen_name->tag=0;gen_name->name->other_name=$othername.text;}
	|	tag1 {gen_name->tag=1;gen_name->name->rfc822name = new_asn1_string(22,$tag1.text->length,$tag1.text->value);
	if(check_string("^((([[:alpha:]]|[[:digit:]]|!|#|\\$|\%|&|'|\\*|\\+|\\-|/|=|\\?|\\^|_|`|{|}|\\||~|)+(\\.([[:alpha:]]|[[:digit:]]|!|#|\\$|\%|&|'|\\*|\\+|\\-|/|=|\\?|\\^|_|`|{|}|\\||~|)+)*)|(\"([\\x00-\\x1F]|[\\x21-\\x27]|[\\x2A-\\x5B]|[\\x5D-\\x7E]|\\\\.?)*\"))@((([[:alpha:]]|[[:digit:]])(([[:alpha:]]|[[:digit:]]|\\-)*([[:alpha:]]|[[:digit:]]))?)(\\.(([[:alpha:]]|[[:digit:]])(([[:alpha:]]|[[:digit:]]|\\-)*([[:alpha:]]|[[:digit:]]))?))+|\\[([\\x01-\\x1F]|[\\x21-\\x5A]|\\\\|[\\x5E-\\x7F])+\\])$",$tag1.text->value,$tag1.text->length))
		warning |= BAD_EMAIL_FORMAT_WARNING;
	}
	|	tag2 {gen_name->tag=2;gen_name->name->DNSname = new_asn1_string(22,$tag2.text->length,$tag2.text->value);
	if(check_string("^([[:alpha:]]|[[:digit:]])(([[:alpha:]]|[[:digit:]]|\\-)*([[:alpha:]]|[[:digit:]]))?(\\.([[:alpha:]]|[[:digit:]])(([[:alpha:]]|[[:digit:]]|\\-)*([[:alpha:]]|[[:digit:]]))?)*$",$tag2.text->value,$tag2.text->length))
		warning|=BAD_DNS_FORMAT_WARNING;
	}
	|	constructedTag3 {sequence_pointer =counter_list; gen_name->tag=3; gen_name->name->x400_addr = malloc(sizeof(x400_address));gen_name->name->x400_addr->standard_attributes=malloc(sizeof(standard_attrs));} 
		standardAttrs definedAttrs? extensionAttrs?
	|	constructedTag4 notEmptyName {gen_name->tag=4;gen_name->name->dn = dname;}
	|	constructedTag5 edipartyname {gen_name->tag=5;gen_name->name->edi=$edipartyname.text;}
	|	tag6 {gen_name->tag=6;gen_name->name->uri = new_asn1_string(22,$tag6.text->length,$tag6.text->value);
	if(check_string("^[[:alpha:]]([[:alpha:]]|[[:digit:]]|\\+|\\-|\\.)*:([[:alpha:]]|[[:digit:]]|\\-|\\.|_|~|:|\\?|/|\\[|\\]|@|!|\\$|&|'|\\(|\\)|\\*|\\+|,|;|=|\%)*(\\?([[:alpha:]]|[[:digit:]]|\\-|\\.|_|~|:|\\?|/|@|!|\\$|&|'|\\(|\\)|\\*|\\+|,|;|=|\%)*)?\\z",$tag6.text->value,$tag6.text->length))
		warning |= BAD_URI_FORMAT_WARNING;
	}
	|	tag7 {gen_name->tag=7;gen_name->name->IP_addr = new_asn1_string(4,$tag7.text->length,$tag7.text->value);}
	|	tag8 {gen_name->tag=8;
		oid_array *test = malloc(sizeof(oid_array));
		test->oid = malloc(sizeof(mpz_t)*($tag8.text->length+2));
		printf("It's ok til here \n");
		int oid_len = compute_oid_value($tag8.text->value,$tag8.text->length,test->oid);
		printf("Value computed \n");
		int i;
		char **oid_numbers;
		oid_numbers = malloc(sizeof(char *)*oid_len);
		int oid_obj_len = 0;
		for(i=0;i<oid_len;i++)
		{
			oid_numbers[i] = mpz_get_str(NULL,10,test->oid[i]);
			oid_obj_len += strlen(oid_numbers[i]);
		}
		char *oid_value = malloc(oid_obj_len+oid_len);
		strcpy(oid_value,oid_numbers[0]);
		for(i=1;i<oid_len;i++)
		{
			strcat(oid_value,".");
			strcat(oid_value,oid_numbers[i]);
		}
		printf("OID Value is \%s \n",oid_value);
		test->len = oid_len;	
		int new_nid = OBJ_txt2nid(oid_value);
		if(new_nid == NID_undef)
			new_nid = OBJ_create(oid_value,oid_value,oid_value);
		gen_name->name->registered_id = OBJ_nid2obj(new_nid);
		free(test);
	}
	;
	
othername returns[other_name *text]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	oid constructedTag0 any{$text=malloc(sizeof(other_name));
		$text->oid=$oid.text->obj;
		$text->value=$any.text;
	}; //it should be any
	
edipartyname returns[EDIPARTYNAME *text]  @init{$text = malloc(sizeof(EDIPARTYNAME));$text->nameAssigner = NULL;} 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	(tag0{$text->nameAssigner=new_asn1_string(12,$tag0.text->length,$tag0.text->value);})? tag1{
		$text->partyName = new_asn1_string(12,$tag1.text->length,$tag1.text->value);
	};

standardAttrs @init{ASN1_STRING *str;} 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	sequenceTag (countryName)? (adName)? ( {sequence_pointer != NULL}?=> tag_zero=tag0 	
	{if(!(1 <= $tag_zero.text->length && $tag_zero.text->length <= ub_x121_address_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	gen_name->name->x400_addr->standard_attributes->net_addr = new_asn1_string(18,$tag_zero.text->length,$tag_zero.text->value);
	}|) ({sequence_pointer != NULL}?=> tag_one=tag1
	{if(!(1 <= $tag_one.text->length && $tag_one.text->length <= ub_terminal_id_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	gen_name->name->x400_addr->standard_attributes->terminal_id = new_asn1_string(18,$tag_one.text->length,$tag_one.text->value);
	}
	|) (constructedTag2 (numericString {str=$numericString.text;} | print=printString {str=$print.text;})
	{if(!(1 <= str->length && str->length <= ub_domain_name_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	gen_name->name->x400_addr->standard_attributes->private_domain_name = str;
	}
	)? (tag_three=tag3
	{if(!(1 <= $tag_three.text->length && $tag_three.text->length <= ub_organization_name_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	gen_name->name->x400_addr->standard_attributes->organization_name = new_asn1_string(19,$tag_three.text->length,$tag_three.text->value);
	}
	)? (tag4
	{if(!(1 <= $tag4.text->length && $tag4.text->length <= ub_numeric_user_id_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	gen_name->name->x400_addr->standard_attributes->numeric_user_identifier = new_asn1_string(18,$tag4.text->length,$tag4.text->value);
	}
	)? 
	({sequence_pointer != NULL}?=> constructedTag5 (t0=tag0 
	{if(!(1 <= $t0.text->length && $t0.text->length <= ub_surname_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	gen_name->name->x400_addr->standard_attributes->surname = new_asn1_string(19,$t0.text->length,$t0.text->value);
	})
	 ({sequence_pointer != NULL}?=> t1=tag1
	{if(!(1 <= $t1.text->length && $t1.text->length <= ub_given_name_length))
		printf("Error on string length constraint \n");
	gen_name->name->x400_addr->standard_attributes->given_name = new_asn1_string(19,$t1.text->length,$t1.text->value);
	}
	|) ({sequence_pointer != NULL}?=> t2=tag2
	{if(!(1 <= $t2.text->length && $t2.text->length <= ub_initials_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	gen_name->name->x400_addr->standard_attributes->initials = new_asn1_string(19,$t2.text->length,$t2.text->value);
	}
	|) (t3=tag3
	{if(!(1 <= $t3.text->length && $t3.text->length <= ub_generation_qualifier_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	gen_name->name->x400_addr->standard_attributes->generation_qualifier = new_asn1_string(19,$t3.text->length,$t3.text->value);
	}
	)?|) (constructedTag6 {gen_name->name->x400_addr->standard_attributes->organizational_unit_names = sk_STRING_POINTER_new_null();} (print=printString 
	{if(!(1 <= $print.text->length && $print.text->length <= ub_organizational_unit_name_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}	
	sk_STRING_POINTER_push(gen_name->name->x400_addr->standard_attributes->organizational_unit_names,$print.text);
	}
	)+ {int len = sk_STRING_POINTER_num(gen_name->name->x400_addr->standard_attributes->organizational_unit_names); 
	if(!(1<len &&len<= ub_organizational_units))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	})?;
	
countryName @init{ASN1_STRING *str;}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	appTag1 (numericString {str=$numericString.text;} | printString {str=$printString.text;}) 
	{if(str->length != ub_country_name_numeric_length)
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	gen_name->name->x400_addr->standard_attributes->country_name = str;
	};

adName @init{ASN1_STRING *str;}	
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	appTag2 (numericString {str=$numericString.text;} | printString {str=$printString.text;})
	{if(str->length > ub_domain_name_length)
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	gen_name->name->x400_addr->standard_attributes->ad_name = str;
	}	
	;

definedAttrs 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	sequenceTag {gen_name->name->x400_addr->defined_attributes = sk_DEFINED_ATTRS_POINTER_new_null();} (definedAttr
	{
	sk_DEFINED_ATTRS_POINTER_push(gen_name->name->x400_addr->defined_attributes,$definedAttr.text);
	}
	)+
	{
		int len = sk_DEFINED_ATTRS_POINTER_num(gen_name->name->x400_addr->defined_attributes);
		if(len > ub_domain_defined_attributes)
		{
			printf("Error on defined attributes stack size \n");
			exit(DEFINED_ATTRS_STACK_SIZE_ERROR);
		}	
	};
	
definedAttr returns [DEFINED_ATTRS_POINTER text]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	sequenceTag type=printString value=printString {
		$text = malloc(sizeof(defined_attrs));
		if(!(1<= $type.text->length && $type.text->length <= ub_domain_defined_attribute_type_length))
		{
			printf("Attribute String length constraint not satisfied \n");
			warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
		}
		$text->type = $type.text;
		if(!(1<= $value.text->length && $value.text->length <= ub_domain_defined_attribute_value_length))
		{
			printf("Attribute String length constraint not satisfied \n");
			warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
		}
		$text->value = $value.text;
		
	};
	
extensionAttrs 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	set {gen_name->name->x400_addr->extensions_attributes = sk_EXTENSIONS_ATTRS_POINTER_new_null();}(extensionAttr
	{sk_EXTENSIONS_ATTRS_POINTER_push(gen_name->name->x400_addr->extensions_attributes,$extensionAttr.text);})+
	{
		int len = sk_EXTENSIONS_ATTRS_POINTER_num(gen_name->name->x400_addr->extensions_attributes);
		if(len > ub_extensions_attributes)
		{
			printf("Error on extension attributes stack size \n");
			exit(EXTENSIONS_ATTRS_STACK_SIZE_ERROR);
		}
	};
	
extensionAttr returns [EXTENSIONS_ATTRS_POINTER text] @init{ASN1_STRING *str_num_or_print;
	#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:	sequenceTag {$text=malloc(sizeof(extensions_attrs));}
	 (tagInt1 constructedTag1 str=printString {$text->type=1;$text->value = malloc(sizeof(EXTS_ATTRS_VALUE)); 
	 if(!(1<= $str.text->length && $str.text->length <= ub_common_name_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	$text->value->str_value=$str.text;} | tagInt2 constructedTag1 strtel=teletexString { $text->type=2;$text->value = malloc(sizeof(EXTS_ATTRS_VALUE));
	if(!(1<= $strtel.text->length && $strtel.text->length <= ub_common_name_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	 $text->value->str_value=$strtel.text;
	 }| tagInt3 constructedTag1 strtel=teletexString { $text->type=3;$text->value = malloc(sizeof(EXTS_ATTRS_VALUE));
	 if(!(1<= $strtel.text->length && $strtel.text->length <= ub_organization_name_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	 $text->value->str_value=$strtel.text;
	 }
	| tagInt4 constructedTag1 set (t0=tag0 {$text->type=4;
	$text->value = malloc(sizeof(EXTS_ATTRS_VALUE));
	 $text->value->personal_name = malloc(sizeof(PERSONAL_NAME));
	 if(!(1<= $t0.text->length && $t0.text->length <= ub_surname_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	 $text->value->personal_name->surname = new_asn1_string(20,$t0.text->length,$t0.text->value);
	 $text->value->personal_name->given_name = NULL;
	 $text->value->personal_name->initials = NULL;
	 $text->value->personal_name->gen_qualifier = NULL;
	}) ( |{sequence_pointer != NULL}?=> t1=tag1{
	 if(!(1<= $t1.text->length && $t1.text->length <= ub_given_name_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	 $text->value->personal_name->given_name = new_asn1_string(20,$t1.text->length,$t1.text->value);	
	}) ( |{sequence_pointer != NULL}?=> tag2{
	 if(!(1<= $tag2.text->length && $tag2.text->length <= ub_initials_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	 $text->value->personal_name->initials = new_asn1_string(20,$tag2.text->length,$tag2.text->value);	
	}) (tag3{
	 if(!(1<= $tag3.text->length && $tag3.text->length <= ub_generation_qualifier_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	 $text->value->personal_name->gen_qualifier = new_asn1_string(20,$tag3.text->length,$tag3.text->value);
	})? | tagInt5 constructedTag1 sequenceTag {$text->type=5;$text->value = malloc(sizeof(EXTS_ATTRS_VALUE));
	$text->value->organizational_unit_names = sk_STRING_POINTER_new_null();
	}
	(strtel=teletexString
	{
	if(!(1 <= $strtel.text->length && $strtel.text->length <= ub_organizational_unit_name_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	sk_STRING_POINTER_push($text->value->organizational_unit_names,$strtel.text);
	}
	)+ {int len = sk_STRING_POINTER_num($text->value->organizational_unit_names); 
	if(!(1<len &&len<= ub_organizational_units))
	{
		printf("Error on organizational units stack size \n");
		exit(OU_STACK_SIZE_ERROR);
	}
	} | tagInt7 constructedTag1 str=printString {$text->type=7;$text->value=malloc(sizeof(EXTS_ATTRS_VALUE));
	 if(!(1<= $str.text->length && $str.text->length <= ub_pds_name_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	 $text->value->str_value=$str.text;	
	}
	| tagInt8 constructedTag1 (strnum=numericString {$text->type=8;$text->value=malloc(sizeof(EXTS_ATTRS_VALUE));
	 if($strnum.text->length != ub_country_name_numeric_length)
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	 $text->value->str_value=$strnum.text;	
	}
	| str=printString{$text->type=8;$text->value=malloc(sizeof(EXTS_ATTRS_VALUE));
	 if($str.text->length != ub_country_name_alpha_length)
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	 $text->value->str_value=$str.text;	
	}
	) 
	| tagInt9 constructedTag1 (strnum=numericString {str_num_or_print = $strnum.text;}| str=printString {str_num_or_print=$str.text;}){$text->type=9;$text->value=malloc(sizeof(EXTS_ATTRS_VALUE));
	 if(!(1<= str_num_or_print->length && str_num_or_print->length <= ub_postal_code_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	 $text->value->str_value=str_num_or_print;	
	} 
	| (tagInt10 {$text->type=10;}| tagInt11 {$text->type=11;}| tagInt12 {$text->type=12;}| tagInt13 {$text->type=13;}| tagInt14 {$text->type=14;}| tagInt15 {$text->type=15;}
	| tagInt17 {$text->type=17;}| tagInt18 {$text->type=18;}| tagInt19 {$text->type=19;}| tagInt20 {$text->type=20;}| tagInt21{$text->type=21;}) 
	constructedTag1 set {$text->value=malloc(sizeof(EXTS_ATTRS_VALUE));$text->value->pds_parameter=malloc(sizeof(PDS_PARAMETER));
	$text->value->pds_parameter->printable = NULL;$text->value->pds_parameter->teletex=NULL;
	}
	(str=printString{
	 if(!(1<= $str.text->length && $str.text->length <= ub_pds_parameter_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	$text->value->pds_parameter->printable=$str.text;
	})? (t61=teletexString{
	 if(!(1<= $t61.text->length && $t61.text->length <= ub_pds_parameter_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	 $text->value->pds_parameter->teletex=$t61.text;	
	})? 
	| tagInt16 constructedTag1 set {$text->type = 16;$text->value=malloc(sizeof(EXTS_ATTRS_VALUE));$text->value->upa=malloc(sizeof(UNFORMATTED_POSTAL_ADDRESS));
	$text->value->upa->printable_addr = NULL;$text->value->upa->t_string=NULL;
	} (sequenceTag {$text->value->upa->printable_addr = sk_STRING_POINTER_new_null();} (str=printString
	{if(!(1 <= $str.text->length && $str.text->length <= ub_pds_parameter_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	sk_STRING_POINTER_push($text->value->upa->printable_addr,$str.text);
	})+
	{int len = sk_STRING_POINTER_num($text->value->upa->printable_addr); 
	if(!(1<len && len<= ub_pds_physical_address_lines))
	{
		printf("Error on organizational units stack size \n");
		exit(OU_STACK_SIZE_ERROR);
	}
	} )? (t61=teletexString{
	 if(!(1<= $t61.text->length && $t61.text->length <= ub_unformatted_address_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	 $text->value->upa->t_string=$t61.text;	
	})?  
	| tagInt22 constructedTag1 {$text->type=22;$text->value=malloc(sizeof(EXTS_ATTRS_VALUE));} (t0=tag0 {$text->value->e163_4 = malloc(sizeof(E163_4_ADDR));
	if(!(1<= $t0.text->length && $t0.text->length <= ub_e163_4_number_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	 $text->value->e163_4->number=new_asn1_string(18,$t0.text->length,$t0.text->value);
	 $text->value->e163_4->sub_address=NULL;	
	} ({sequence_pointer != NULL}?=> t1=tag1{
	 if(!(1<= $t1.text->length && $t1.text->length <= ub_e163_4_sub_address_length))
	{
		printf("Attribute String length constraint not satisfied \n");
		warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
	}
	 $text->value->e163_4->sub_address=new_asn1_string(18,$t1.text->length,$t1.text->value);		
	}| ) | constructedTag0 {$text->value->psap=malloc(sizeof(PSAP_ADDR));$text->value->psap->p_selector=NULL;
	$text->value->psap->s_selector=NULL;$text->value->psap->t_selector=NULL;$text->value->psap->n_addresses=NULL;
	}(constructedTag0 p=octetstring {$text->value->psap->p_selector=$p.text;})? (constructedTag1 s=octetstring {$text->value->psap->s_selector=$s.text;})? 
	(constructedTag2 t=octetstring {$text->value->psap->p_selector=$t.text;})? (constructedTag3 set {$text->value->psap->n_addresses=sk_STRING_POINTER_new_null();} 
	(n=octetstring{
	sk_STRING_POINTER_push($text->value->psap->n_addresses,$n.text);
	})+)?)
	| tagInt23 constructedTag1 i23=integer { $text->type=23;$text->value = malloc(sizeof(EXTS_ATTRS_VALUE));
	 if(!($i23.text->length==1 || ($i23.text->length==2 && $i23.text->data[0] & 254 == 0)))
	 {
	 	printf("Error on integer bounds \n");
	 	warning|=INTEGER_BOUNDS_WARNING;
	 }	
	 $text->value->str_value=$i23.text;
	 }| tagInt6 constructedTag1 sequenceTag {$text->type=6;$text->value=malloc(sizeof(EXTS_ATTRS_VALUE));$text->value->domain_defined=sk_DEFINED_ATTRS_POINTER_new_null();
	 }(sequenceTag type=teletexString value=teletexString{
		defined_attrs* def = malloc(sizeof(defined_attrs));
		if(!(1<= $type.text->length && $type.text->length <= ub_domain_defined_attribute_type_length))
		{
			printf("Attribute String length constraint not satisfied \n");
			warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
		}
		def->type = $type.text;
		if(!(1<= $value.text->length && $value.text->length <= ub_domain_defined_attribute_value_length))
		{
			printf("Attribute String length constraint not satisfied \n");
			warning|=ATTRIBUTE_STRING_LENGTH_WARNING;
		}
		def->value = $value.text;	 
	 	sk_DEFINED_ATTRS_POINTER_push($text->value->domain_defined,def);
	 }
	 )+{
		int len = sk_DEFINED_ATTRS_POINTER_num($text->value->domain_defined);
		if(len > ub_domain_defined_attributes)
		{
			printf("Error on defined attributes stack size \n");
			exit(DEFINED_ATTRS_STACK_SIZE_ERROR);
		}	
	}
	| i=onlyTag0 any {mpz_t length,value;mpz_init_set_ui(length,$i.text->length);mpz_init_set_ui(value,0);compute_integer($i.text->value,length,value);
	if(!(0<=mpz_get_ui(value) && mpz_get_ui(value) <= ub_extensions_attributes))
	 {
	 	printf("Error on integer bounds \n");
	 	warning|=INTEGER_BOUNDS_WARNING;
	 }
	$text->type=mpz_get_ui(value);$text->value=malloc(sizeof(EXTS_ATTRS_VALUE));$text->value->any=$any.text;
	});

name @init{dname = sk_X509_DNAME_ENTRY_new_null();
	#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:	sequenceTag rdns {cert->issuer = dname;};

rdns 	@init{
	#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:	set {set_pointer = counter_list;}rdn rdns | ;

notEmptyName @init{dname = sk_X509_DNAME_ENTRY_new_null();
	#ifdef DEBUG 
	push_rule(__func__); 
	#endif	}	
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	: sequenceTag rdnsNotEmpty;
	
rdnsNotEmpty 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	set {set_pointer = counter_list;}rdn (rdnsNotEmpty | );

rdn	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	sequenceTag dn ({set_pointer != NULL}?=>rdn | );

dn    @init{ASN1_OBJECT *obj;ASN1_STRING *str;
	#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:((cnoid {obj = $cnoid.obj;}| oidon {obj = $oidon.obj;}| oidname {obj = $oidname.obj;}| surnameoid {obj = $surnameoid.obj;}| 
		givenoid {obj = $givenoid.obj;}| initoid {obj = $initoid.obj;}| genqualifieroid {obj = $genqualifieroid.obj;}| localoid {obj = $localoid.obj;}| ouoid {obj = $ouoid.obj;}|
		 sorpoid {obj = $sorpoid.obj;}|titleoid {obj = $titleoid.obj;}| pseudooid {obj = $pseudooid.obj;}) directoryString {str=$directoryString.text;} 
		/*{
		printf("\%x \%d \n",dname->modified,$directoryString.text->length);
		if(!X509_NAME_add_entry_by_OBJ(dname,obj,$directoryString.text->type,$directoryString.text->data,$directoryString.text->length,-1,0))
			printf("Error in x509Name \n");
		int loc = X509_NAME_get_index_by_OBJ(dname,obj,-1);
		printf("it's here \%d \n",loc);
		X509_NAME_ENTRY *ne = X509_NAME_get_entry(dname,loc);
		printf("it's here \%x \n",ne);
		printf("name entry is \%d \%d \%s \n",ne->value->type,ne->value->length,ne->value->data);
		ASN1_STRING *out = malloc(sizeof(ASN1_STRING));
		out->data = malloc($directoryString.text->length+1);
		int ret = ASN1_mbstring_ncopy(&out,$directoryString.text->data,$directoryString.text->length,$directoryString.text->type,ASN1_STRING_TABLE_get(NID_commonName)->mask,1,1);
		
		printf("ret value is \%d and type ret is \%d \n",ret,out->type);
		} */
		
		|(dnoid {obj = $dnoid.obj;} | countryoid {obj = $countryoid.obj;}| serialoid {obj = $serialoid.obj;}) (printString {str=$printString.text;} | stria5=ia5String 
		{str=$stria5.text;printf("Warning: ia5 not allowed \n");})
		{str->type=MBSTRING_ASC;printf("setting to ASCII \n");}
		|legacyemailoid stria5=ia5String {obj = $legacyemailoid.obj;str=$stria5.text;str->type=MBSTRING_ASC;})
		{
			ASN1_STRING *out = malloc(sizeof(ASN1_STRING));
			out->data = NULL;
			ASN1_STRING_TABLE *tbl = ASN1_STRING_TABLE_get(OBJ_obj2nid(obj));
			if(ASN1_mbstring_ncopy(&out,str->data,str->length,str->type,tbl->mask,tbl->minsize,tbl->maxsize) == -1)
			{
				printf("DN String length constraint not satisfied \n");
				exit(X509_DNAME_ERROR);
			}
			X509_DNAME_ENTRY *entry = malloc(sizeof(X509_DNAME_ENTRY));
			entry->string_name = malloc(sizeof(X509_STRING_NAME));
			entry->string_name->oid = obj;
			entry->string_name->value = out; 
			sk_X509_DNAME_ENTRY_push(dname,entry);
		}
		|oid any 
		{
		X509_DNAME_ENTRY *entry = malloc(sizeof(X509_DNAME_ENTRY));
		entry->other_name = malloc(sizeof(other_name));	
		entry->other_name->oid = $oid.text->obj;
		entry->other_name->value = $any.text;
		sk_X509_DNAME_ENTRY_push(dname,entry);
		}
		; //needs to be specialized in all different cases

directoryString returns [ASN1_STRING *text]
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:	teletexString {$text = $teletexString.text;$text->type = MBSTRING_ASC;}
	|	printString {$text = $printString.text;$text->type = MBSTRING_ASC;}
	|	utf8String {$text = $utf8String.text;$text->type = MBSTRING_UTF8;}
	|	univerString {$text = $univerString.text;$text->type = MBSTRING_UNIV;}
	|	bmpString {$text = $bmpString.text;$text->type = MBSTRING_BMP;}
	|	ia5String {$text = $ia5String.text;$text->type = MBSTRING_ASC;warning |= IA5STRING_MISUSE_WARNING;}//this should not be here! Remove it!
	;

signature
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	bitstring
	{
	cert->signature = malloc(sizeof(X509_SIGNATURE));
	cert->signature->sign = $bitstring.text;
	}
	;
	
dsa_signature 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	constructedBitString sequenceTag r=integer s=integer 
	{
	cert->signature=malloc(sizeof(X509_SIGNATURE));
	cert->signature->dsa_sign = malloc(sizeof(DSA_signature));
	cert->signature->dsa_sign->r = $r.text;
	cert->signature->dsa_sign->s = $s.text;
	};
	
	
//base types

critical returns[int bool]	
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}:
		truevalue {$bool=1;} | falsevalue {$bool=0;};

	
time_span returns [ASN1_TIME *text]
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}:
	 	utc {$text=$utc.text;} | genTime {$text=$genTime.text;};
any returns[ANY* text]	@init{any_pointer = counter_list;printf("any_pointer is \%x \n",any_pointer);ANY* result = NULL;
	#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}:

 ({any_pointer != NULL}?=> {printf("any token is parsed \n");} anyToken 
	{
	if(!result)
	{
		result = malloc(sizeof(ANY));
		$text = result;
	}
	else
	{
		result->next=malloc(sizeof(ANY));
		result=result->next;
	}
	result->el=$anyToken.text;
	result->next=NULL;
	} )+;
anyToken returns[void *text]	
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}:
		teletexString {$text=$teletexString.text;}
	|	ia5String {$text=$ia5String.text;}
	|	bmpString {$text=$bmpString.text;}
	|	utf8String {$text=$utf8String.text;}
	|	printString {$text=$printString.text;}
	|	univerString {$text=$univerString.text;}
	|	visibleString {$text=$visibleString.text;}
	|	generalString {$text=$generalString.text;}
	|	graphicString {$text=$graphicString.text;}
	|	videoString {$text=$videoString.text;}
	|	integer {$text=$integer.text;}
	|	bitstring {$text=$bitstring.text;}
	|	constructedOctetString {$text = new_asn1_string (36,0,NULL);}
	|	time_span {$text=$time_span.text;}
	|	critical {$text=$critical.text;}
	|	set {$text=new_asn1_string(49,0,NULL);}
	|	null {$text=new_asn1_string(5,0,NULL);}
	|	octetstring {$text=$octetstring.text;}
	|	sequenceTag {$text=new_asn1_string(48,0,NULL);}
	|	oid {$text=$oid.text->obj;}//there is no point in having a known oid in any field, because it's more clever to use it where the standard suggest it
	|	constructedTag0 {$text=new_asn1_string(160,0,NULL);}
	|	tag0 {$text=new_asn1_string(80,$tag0.text->length,$tag0.text->value);}
	|	constructedTag1 {$text=new_asn1_string(161,0,NULL);}
	|	tag1 {$text=new_asn1_string(81,$tag1.text->length,$tag1.text->value);}
	|	constructedTag2 {$text=new_asn1_string(162,0,NULL);}
	|	tag2 {$text=new_asn1_string(82,$tag2.text->length,$tag2.text->value);}
	|	constructedTag3 {$text=new_asn1_string(163,0,NULL);}
	|	tag3 {$text=new_asn1_string(83,$tag3.text->length,$tag3.text->value);}
	|	constructedTag4 {$text=new_asn1_string(164,0,NULL);}
	|	tag4 {$text=new_asn1_string(84,$tag4.text->length,$tag4.text->value);}
	|	constructedTag5 {$text=new_asn1_string(165,0,NULL);}
	|	tag5 {$text=new_asn1_string(85,$tag5.text->length,$tag5.text->value);}
	|	constructedTag6 {$text=new_asn1_string(166,0,NULL);}
	|	tag6 {$text=new_asn1_string(86,$tag6.text->length,$tag6.text->value);}
	|	constructedTag7 {$text=new_asn1_string(167,0,NULL);}
	|	tag7 {$text=new_asn1_string(87,$tag7.text->length,$tag7.text->value);}
	|	constructedTag8 {$text=new_asn1_string(168,0,NULL);}
	|	tag8 {$text=new_asn1_string(88,$tag8.text->length,$tag8.text->value);}
	//|	tag1Printable {$text=new_asn1_string(81,$tag1Printable.text->length,$tag1Printable.text->value);}
	//|	tag2Printable {$text=new_asn1_string(82,$tag2Printable.text->length,$tag2Printable.text->value);}
	;
	
octetstring returns [ASN1_OCTET_STRING* text]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OctetTag val {
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($OctetTag.text->chars,length);
		$text = (ASN1_OCTET_STRING *) new_asn1_string (4,mpz_get_ui(length),$val.text);
	}
	;
	
integer returns [ASN1_INTEGER *text]	
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}:
	 	integerAbove3 {$text=$integerAbove3.text;}
	|	int0 {unsigned char *value = malloc(1);value[0]=0;$text= (ASN1_INTEGER *) new_asn1_string(2,1,value);}
	|	int1 {unsigned char *value = malloc(1);value[0]=1;$text= (ASN1_INTEGER *) new_asn1_string(2,1,value);}
	|	int2 {unsigned char *value = malloc(1);value[0]=2;$text= (ASN1_INTEGER *) new_asn1_string(2,1,value);}
	;	

integerAbove3 returns [ASN1_INTEGER *text]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	IntTag val {
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($IntTag.text->chars,length);
		$text= (ASN1_INTEGER *) new_asn1_string(2,mpz_get_ui(length),$val.text);
	}
	;
	
int0 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	Int0{entire_encoding(1);printf("Int0 \n");};

int1	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	Int1{entire_encoding(1);printf("Int1 \n");};

int2	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	Int2{entire_encoding(1);printf("Int2 \n");};
	
bitstring returns [ASN1_STRING* text]	
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}:
		BitStringTag val {
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($BitStringTag.text->chars,length);
		ASN1_STRING *bs;
		bs = malloc(sizeof(ASN1_STRING));
		compute_bitstring ($val.text,mpz_get_ui(length),bs);
		$text = bs;
	}
	|	BitStringKeyCert val{
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($BitStringKeyCert.text->chars,length);
		ASN1_STRING *bs;
		bs = malloc(sizeof(ASN1_STRING));
		if((unsigned char) $BitStringKeyCert.text->chars[2] > 8)
			exit(BAD_BITSTRING_ENCODING_ERROR);
		unsigned char mask = 255 << (unsigned char) $BitStringKeyCert.text->chars[2];
		bs->type =3;
		bs->length = mpz_get_ui(length)-1;
		bs->data=malloc(bs->length);
		$val.text[bs->length-1] &= mask;
		unsigned long i;
		for(i=0;i<bs->length;i++)
			bs->data[i]=$val.text[i];
		$text = bs;
		printf("It's bit string \n");
	}
	;
	
bitstringCertSign 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	BitStringKeyCert {
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($BitStringKeyCert.text->chars,length);
		ASN1_STRING *bs;
		bs = malloc(sizeof(ASN1_STRING));
		unsigned char mask = 255 << (unsigned char) $BitStringKeyCert.text->chars[2];
		bs->type=3;
		bs->length = mpz_get_ui(length)-1;
		bs->data=malloc(bs->length);
		$BitStringKeyCert.text->chars[bs->length+2] &= mask;
		unsigned long i;
		for(i=0;i<bs->length;i++)
			bs->data[i]=$BitStringKeyCert.text->chars[i+3];
		key_usage_ext->value->keyusage=bs;
		printf("It's bit string cert sign \n");
	}; 

/*generaloid returns[ASN1_OBJECT *obj]
	:	oid {obj = $oid.text->obj;}
	|
	(	object=aiaoid 
	|	object=anyusageoid 
	|	object=basis2oid 
	|	object=bcoid 
	|	object=caissueroid 
	|	object=certpolioid 
	|	object=clientauthoid 
	|	object=cnoid 
	|	object=codesignoid 
	|	object=countryoid 
	|	object=cpsoid 
	|	object=crldpoid 
	|	object=dhpkoid 
	|	object=dnoid 
	|	object=dsapkoid
	|	object=ecpkoid 
	|	object=ekuoid
	|	object=emailprotectoid
	|	object=freshcrloid
	|	object=genqualifieroid
	|	object=givenoid
	|	object=gnoid
	|	object=gost01pkoid
	|	object=gost01signoid
	|	object=gost94pkoid
	|	object=gost94signoid
	|	object=inhibitanyoid
	|	object=initoid
	|	object=issaltoid
	|	object=keapkoid
	|	object=keyusageoid
	|	object=legacyemailoid
	|	object=localoid
	|	object=md2rsaoid
	|	object=md5rsaoid
	|	object=mgf1oid
	|	object=nameoid
	|	object=ocspoid
	|	object=ocspsignoid
	|	object=oidname
	|	object=oidon
	|	object=ouoid
	|	object=polconstraintsoid
	|	object=polmapoid
	|	object=ppoid
	|	object=primeoid
	|	object=pseudooid
	|	object=pspecoid
	|	object=rsaoaepoid
	|	object=rsapkoid
	|	object=rsapssoid
	|	object=serialoid
	|	object=serverauthoid
	|	object=sha1dsaoid
	|	object=sha1ecoid
	|	object=sha1oid
	|	object=sha1rsaoid
	|	object=sha224dsaoid
	|	object=sha224ecoid
	|	object=sha224oid
	|	object=sha224rsaoid
	|	object=sha256dsaoid
	|	object=sha256ecoid
	|	object=sha256oid
	|	object=sha256rsaoid
	|	object=sha384ecoid
	|	object=sha384oid
	|	object=sha384rsaoid
	|	object=sha512ecoid
	|	object=sha512oid
	|	object=sha512rsaoid
	|	object=skioid
	|	object=siaoid
	|	object=sorpoid
	|	object=subaltoid
	|	object=subdiroid
	|	object=surnameoid
	|	object=timestampoid
	|	object=titleoid
	|	object=tpoid
	|	object=unoticeoid) {obj = $object.obj;}
	;*/
	
oid returns [oid_array* text]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag val {
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($OIDTag.text->chars,length);
		oid_array* test;
		int len = mpz_get_ui(length);
		test = malloc(sizeof(oid_array));
		test->oid = malloc(sizeof(mpz_t)*(len+2));
		printf("It's ok til here \n");
		int oid_len = compute_oid_value($val.text,len,test->oid);
		printf("Value computed \n");
		int i;
		char **oid_numbers;
		oid_numbers = malloc(sizeof(char *)*oid_len);
		int oid_obj_len = 0;
		for(i=0;i<oid_len;i++)
		{
			oid_numbers[i] = mpz_get_str(NULL,10,test->oid[i]);
			oid_obj_len += strlen(oid_numbers[i]);
		}
		char *oid_value = malloc(oid_obj_len+oid_len);
		strcpy(oid_value,oid_numbers[0]);
		for(i=1;i<oid_len;i++)
		{
			strcat(oid_value,".");
			strcat(oid_value,oid_numbers[i]);
		}
		printf("OID Value is \%s \n",oid_value);
		test->len = oid_len;
		int new_nid = OBJ_txt2nid(oid_value);
		if(new_nid == NID_undef)
			new_nid = OBJ_create(oid_value,oid_value,oid_value);
		test->obj = OBJ_nid2obj(new_nid);
		$text = test;
	}
	;
	
cnoid returns [ASN1_OBJECT * obj]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDCN{
		entire_encoding(3);
		$obj = OBJ_nid2obj(NID_commonName);
		printf("it's CN \n");};
	

oidon returns [ASN1_OBJECT * obj] 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDON{
		entire_encoding(3);
		$obj = OBJ_nid2obj(NID_organizationName);
		printf("it's ON \n");};

aiaoid returns [ASN1_OBJECT * obj]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag AIAOID{	
		entire_encoding(8);
		mpz_t oid[9];
		mpz_init_set_ui(oid[0],1);
		mpz_init_set_ui(oid[1],3);
		mpz_init_set_ui(oid[2],6);
		mpz_init_set_ui(oid[3],1);
		mpz_init_set_ui(oid[4],5);
		mpz_init_set_ui(oid[5],5);
		mpz_init_set_ui(oid[6],7);
		mpz_init_set_ui(oid[7],1);
		mpz_init_set_ui(oid[8],1);
		mpz_t index;
		mpz_init(index);
		compute_index(oid,9,index);
		gmp_printf("AIA index is \%Zd \n",index);
		insert_extension(index);
		$obj = OBJ_nid2obj(NID_info_access);
		printf("it's AIA \n");};

siaoid returns [ASN1_OBJECT * obj] 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag SIAOID{
		entire_encoding(8);
		mpz_t oid[9];
		mpz_init_set_ui(oid[0],1);
		mpz_init_set_ui(oid[1],3);
		mpz_init_set_ui(oid[2],6);
		mpz_init_set_ui(oid[3],1);
		mpz_init_set_ui(oid[4],5);
		mpz_init_set_ui(oid[5],5);
		mpz_init_set_ui(oid[6],7);
		mpz_init_set_ui(oid[7],1);
		mpz_init_set_ui(oid[8],11);
		mpz_t index;
		mpz_init(index);
		compute_index(oid,9,index);
		insert_extension(index);
		$obj = OBJ_nid2obj(NID_sinfo_access);
		printf("it's SIA \n");};

akioid returns [ASN1_OBJECT * obj] 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDAKI{
		entire_encoding(3);
		mpz_t index;
		mpz_init_set_ui(index,2035188);
		insert_extension(index);
		$obj = OBJ_nid2obj(NID_authority_key_identifier);
		printf("It's AKI \n");
	};

skioid returns [ASN1_OBJECT * obj] 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDSKI{
		entire_encoding(3);
		mpz_t index;
		mpz_init_set_ui(index,1993020);
		insert_extension(index);
		$obj = OBJ_nid2obj(NID_subject_key_identifier);
		printf("It's SKI \n");
	};

bcoid returns [ASN1_OBJECT * obj]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDBC{
		entire_encoding(3);
		mpz_t index;
		mpz_init_set_ui(index,2003020);
		insert_extension(index);
		$obj = OBJ_nid2obj(NID_basic_constraints);
		printf("It's BC");
	};

polconstraintsoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDPOLCONST{
		entire_encoding(3);
		mpz_t index;
		mpz_init_set_ui(index,2037207);
		insert_extension(index);
		$obj = OBJ_nid2obj(NID_policy_constraints);
		printf("It's POLCONST");
	}
	;
	
certpolioid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDCERTPOL{
		entire_encoding(3);
		mpz_t index;
		mpz_init_set_ui(index,2029137);
		insert_extension(index);
		$obj = OBJ_nid2obj(NID_certificate_policies);
		printf("It's CERTPOL");
	}	;
	
polmapoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDPOLMAP{
		entire_encoding(3);
		mpz_t index;
		mpz_init_set_ui(index,2031153);
		insert_extension(index);
		$obj = OBJ_nid2obj(NID_policy_mappings);
		printf("It's POLMAP");
	};		

keyusageoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDKEYUS{
		entire_encoding(3);
		mpz_t index;
		mpz_init_set_ui(index,1995018);
		insert_extension(index);
		$obj = OBJ_nid2obj(NID_key_usage);
		printf("It's KEYUS");
	};
	
subaltoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDSUBALT{
		entire_encoding(3);
		mpz_t index;
		mpz_init_set_ui(index,1999017);
		insert_extension(index);
		$obj = OBJ_nid2obj(NID_subject_alt_name);
		printf("It's SUBALT");
	} 
	;
	
issaltoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDISSALT{
		entire_encoding(3);
		mpz_t index;
		mpz_init_set_ui(index,2001018);
		insert_extension(index);
		$obj = OBJ_nid2obj(NID_issuer_alt_name);
		printf("It's ISSALT");
	};
	
subdiroid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDSUBDIR{
		entire_encoding(3);
		mpz_t index;
		mpz_init_set_ui(index,1983045);
		insert_extension(index);
		$obj = OBJ_nid2obj(NID_subject_directory_attributes);
		printf("It's SUBDIR");
	};
	
nameoid returns [ASN1_OBJECT * obj]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDNAME{
		entire_encoding(3);
		mpz_t index;
		mpz_init_set_ui(index,2025108);
		insert_extension(index);
		$obj = OBJ_nid2obj(NID_name_constraints);
		printf("It's NAMECONST");
	};		

ekuoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDEXTKEY{
		entire_encoding(3);
		mpz_t index;
		mpz_init_set_ui(index,2039227);
		insert_extension(index);
		$obj = OBJ_nid2obj(NID_ext_key_usage);
		printf("It's EXTKEY");
	};
	
crldpoid returns [ASN1_OBJECT * obj]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDCRL{
		entire_encoding(3);
		mpz_t index;
		mpz_init_set_ui(index,2027122);
		insert_extension(index);
		$obj = OBJ_nid2obj(NID_crl_distribution_points);
		printf("It's CRLDP");
	};
	
inhibitanyoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDINHIBIT{
		entire_encoding(3);
		mpz_t index;
		mpz_init_set_ui(index,2073720);
		insert_extension(index);
		$obj = OBJ_nid2obj(NID_inhibit_any_policy);
		printf("It's INHIBITANY");
	};
	
freshcrloid returns[ASN1_OBJECT *obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		OIDTag OIDFRESHCRL{
		entire_encoding(3);
		mpz_t index;
		mpz_init_set_ui(index,2057452);
		insert_extension(index);
		$obj = OBJ_nid2obj(NID_freshest_crl);
		printf("It's INHIBITANY");
	};
	
caissueroid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
		OIDTag CAISSUEROID
	{
		entire_encoding(8);
		$obj = OBJ_nid2obj(NID_ad_ca_issuers);
		printf("It's CAISSUER");	
	}
	;
	
ocspoid returns [ASN1_OBJECT * obj]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OCSPOID{
		entire_encoding(8);
		$obj = OBJ_nid2obj(NID_ad_OCSP);
		printf("It's OCSP");	
	};
	
carepooid returns [ASN1_OBJECT * obj]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag CAREPOOID{
		entire_encoding(8);
		$obj = OBJ_nid2obj(NID_caRepository);
		printf("It's OCSP");	
	};
	
tspoid returns [ASN1_OBJECT * obj]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag TSPOID{
		entire_encoding(8);
		$obj = OBJ_nid2obj(NID_ad_timeStamping);
		printf("It's OCSP");	
	};
	
cpsoid returns [ASN1_OBJECT * obj] 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag CPSOID
	{
		entire_encoding(8);
		$obj = OBJ_nid2obj(NID_id_qt_cps);
		printf("It's CSP");	
	};
	
unoticeoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag UNOTICEOID
		{
		entire_encoding(8);
		$obj = OBJ_nid2obj(NID_id_qt_unotice);
		printf("It's UNOTICE");	
	};
	
oidname returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag NAMEOID {
		entire_encoding(3);
		$obj = OBJ_nid2obj(NID_name);
		printf("it's NAMEOID \n");};
		
surnameoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag SURNAMEOID{
		entire_encoding(3);
		$obj = OBJ_nid2obj(NID_surname);
		printf("it's SURNAME \n");};
		
givenoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDGIVENAME{
		entire_encoding(3);
		$obj = OBJ_nid2obj(NID_givenName);
		printf("it's ON \n");};

initoid returns [ASN1_OBJECT * obj]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDINIT{
		entire_encoding(3);
		$obj = OBJ_nid2obj(NID_initials);
		printf("it's ON \n");};
		
genqualifieroid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDGENQUALIFIER{
		entire_encoding(3);
		$obj = OBJ_nid2obj(NID_generationQualifier);
		printf("it's ON \n");};
		
localoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDLOCAL{
		entire_encoding(3);
		$obj = OBJ_nid2obj(NID_localityName);
		printf("it's ON \n");};
		
sorpoid returns [ASN1_OBJECT * obj] 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDSORP{
		entire_encoding(3);
		$obj = OBJ_nid2obj(NID_stateOrProvinceName);
		printf("it's ON \n");};
		
ouoid returns [ASN1_OBJECT * obj] 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDOU{
		entire_encoding(3);
		$obj = OBJ_nid2obj(NID_organizationalUnitName);
		printf("it's ON \n");};

titleoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDTITLE{
		entire_encoding(3);
		$obj = OBJ_nid2obj(NID_title);
		printf("it's ON \n");};
		
dnoid returns [ASN1_OBJECT * obj]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDDNQUALIFIER{
		entire_encoding(3);
		$obj = OBJ_nid2obj(NID_dnQualifier);
		printf("it's ON \n");};
		
countryoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDCOUNTRY{
		entire_encoding(3);
		$obj = OBJ_nid2obj(NID_countryName);
		printf("it's ON \n");};
		
serialoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDSERIAL{
		entire_encoding(3);
		$obj = OBJ_nid2obj(NID_serialNumber);
		printf("it's ON \n");};
		
pseudooid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OIDPSEUDO{
		entire_encoding(3);
		$obj = OBJ_nid2obj(NID_pseudonym);
		printf("it's ON \n");};
		
rsapkoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag RSAPKOID{
		entire_encoding(9);
		$obj = OBJ_nid2obj(NID_rsaEncryption);
		printf("it's ON \n");};
		
dsapkoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag DSAPKOID{
		entire_encoding(7);
		$obj = OBJ_nid2obj(NID_dsa);
		printf("it's ON \n");};
		
dhpkoid returns [ASN1_OBJECT * obj] 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag DHPKOID{
		entire_encoding(7);
		$obj = OBJ_nid2obj(NID_dhpublicnumber);
		printf("it's ON \n");};
		
keapkoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag KEAPKOID{
		entire_encoding(9);
		int new_nid = OBJ_txt2nid("2.16.840.1.101.2.1.1.22");
		if(new_nid == NID_undef)
			new_nid = OBJ_create("2.16.840.1.101.2.1.1.22","KEA","key_exchange_algorithm");
		$obj = OBJ_nid2obj(new_nid);
		printf("it's ON \n");};
		
ecpkoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag ECPKOID{
		entire_encoding(7);
		$obj = OBJ_nid2obj(NID_X9_62_id_ecPublicKey);
		printf("it's ON \n");};
		

primeoid returns [ASN1_OBJECT * obj] 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag PRIMEOID{
		entire_encoding(7);
		$obj = OBJ_nid2obj(NID_X9_62_prime_field);
		printf("it's ON \n");};
		

basis2oid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag BASIS2OID{
		entire_encoding(7);
		$obj = OBJ_nid2obj(NID_X9_62_characteristic_two_field);
		printf("it's ON \n");};
		

gnoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag GNBASISOID{
		entire_encoding(9);
		$obj = OBJ_nid2obj(NID_X9_62_onBasis);
		printf("it's ON \n");};

tpoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag TPBASISOID{
		entire_encoding(9);
		$obj = OBJ_nid2obj(NID_X9_62_tpBasis);
		printf("it's ON \n");};

ppoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag PPBASISOID{
		entire_encoding(9);
		$obj = OBJ_nid2obj(NID_X9_62_ppBasis);
		printf("it's ON \n");};
		

sha1oid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag SHA1OID{
		entire_encoding(5);
		$obj = OBJ_nid2obj(NID_sha1);
		printf("it's SHA1 \n");};
sha224oid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag SHA224OID{
		entire_encoding(9);
		$obj = OBJ_nid2obj(NID_sha224);
		printf("it's ON \n");};
		
sha256oid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag SHA256OID{
		entire_encoding(9);
		$obj = OBJ_nid2obj(NID_sha256);
		printf("it's ON \n");};

sha384oid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag SHA384OID{
		entire_encoding(9);
		$obj = OBJ_nid2obj(NID_sha384);
		printf("it's ON \n");};

sha512oid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag SHA512OID{
		entire_encoding(9);
		$obj = OBJ_nid2obj(NID_sha512);
		printf("it's ON \n");};

mgf1oid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag MGF1OID{
		entire_encoding(9);
		$obj = OBJ_nid2obj(NID_mgf1);
		printf("it's ON \n");};

rsapssoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag RSAPSSOID{
		entire_encoding(9);
		$obj = OBJ_nid2obj(NID_rsassaPss);
		printf("it's ON \n");};

rsaoaepoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag RSAOAEPOID{
		entire_encoding(9);
		$obj = OBJ_nid2obj(NID_rsaesOaep);
		printf("it's ON \n");};
		
pspecoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag PSPECOID{
		entire_encoding(9);
		$obj = OBJ_nid2obj(NID_pSpecified);
		printf("it's PSPEC \n");};


md2rsaoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag MD2RSAOID{
		entire_encoding(9);
		$obj = OBJ_nid2obj(NID_md2WithRSAEncryption);
		printf("it's PSPEC \n");};


md5rsaoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag MD5RSAOID{
		entire_encoding(9);
		$obj = OBJ_nid2obj(NID_md5WithRSAEncryption);
		printf("it's PSPEC \n");};

sha1rsaoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag SHA1RSAOID{
		entire_encoding(9);
		$obj = OBJ_nid2obj(NID_sha1WithRSAEncryption);
		printf("it's PSPEC \n");};


sha224rsaoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag SHA224RSAOID{
		entire_encoding(9);
		$obj = OBJ_nid2obj(NID_sha224WithRSAEncryption);
		printf("it's PSPEC \n");};


sha256rsaoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag SHA256RSAOID{
		entire_encoding(9);
		$obj = OBJ_nid2obj(NID_sha256WithRSAEncryption);
		printf("it's PSPEC \n");};


sha384rsaoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag SHA384RSAOID{
		entire_encoding(9);
		$obj = OBJ_nid2obj(NID_sha384WithRSAEncryption);
		printf("it's PSPEC \n");};


sha512rsaoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag SHA512RSAOID{
		entire_encoding(9);
		$obj = OBJ_nid2obj(NID_sha512WithRSAEncryption);
		printf("it's PSPEC \n");};
sha1dsaoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag SHA1DSAOID{
		entire_encoding(7);
		$obj = OBJ_nid2obj(NID_dsaWithSHA1);
		printf("it's PSPEC \n");};
		

sha224dsaoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag SHA224DSAOID{
		entire_encoding(9);
		$obj = OBJ_nid2obj(NID_dsa_with_SHA224);
		printf("it's PSPEC \n");};
		

sha256dsaoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag SHA256DSAOID{
		entire_encoding(9);
		$obj = OBJ_nid2obj(NID_dsa_with_SHA256);
		printf("it's PSPEC \n");};

sha1ecoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag SHA1ECOID{
		entire_encoding(7);
		$obj = OBJ_nid2obj(NID_ecdsa_with_SHA1);
		printf("it's PSPEC \n");};


sha224ecoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag SHA224ECOID{
		entire_encoding(8);
		$obj = OBJ_nid2obj(NID_ecdsa_with_SHA224);
		printf("it's PSPEC \n");};


sha256ecoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag SHA256ECOID{
		entire_encoding(8);
		$obj = OBJ_nid2obj(NID_ecdsa_with_SHA256);
		printf("it's ECDSA SHA256 \n");};

sha384ecoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag SHA384ECOID{
		entire_encoding(8);
		$obj = OBJ_nid2obj(NID_ecdsa_with_SHA384);
		printf("it's PSPEC \n");};		

sha512ecoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag SHA512ECOID{
		entire_encoding(8);
		$obj = OBJ_nid2obj(NID_ecdsa_with_SHA512);
		printf("it's PSPEC \n");};
		

gost94pkoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag GOST94PK{
		entire_encoding(6);
		$obj = OBJ_nid2obj(NID_id_GostR3410_94);
		printf("it's PSPEC \n");};		

gost01pkoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag GOST01PK{
		entire_encoding(6);
		$obj = OBJ_nid2obj(NID_id_GostR3410_2001);
		printf("it's PSPEC \n");};

gost94signoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag GOST94SIGN{
		entire_encoding(6);
		$obj = OBJ_nid2obj(NID_id_GostR3411_94_with_GostR3410_94);
		printf("it's PSPEC \n");};

gost01signoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag GOST01SIGN{
		entire_encoding(6);
		$obj = OBJ_nid2obj(NID_id_GostR3411_94_with_GostR3410_2001);
		printf("it's PSPEC \n");};
		

serverauthoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag SERVERAUTHOID{
		entire_encoding(8);
		$obj = OBJ_nid2obj(NID_server_auth);
		printf("it's SERVERAUTHOID \n");};

clientauthoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag CLIENTAUTHOID{
		entire_encoding(8);
		$obj = OBJ_nid2obj(NID_client_auth);
		printf("it's CLIENTAUTHOID \n");};

codesignoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag CODESIGNOID{
		entire_encoding(8);
		$obj = OBJ_nid2obj(NID_code_sign);
		printf("it's CODESIGNOID \n");};

emailprotectoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag EMAILPROTECTOID{
		entire_encoding(8);
		$obj = OBJ_nid2obj(NID_email_protect);
		printf("it's EMAILPROTECTOID \n");};
		

timestampoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag TIMESTAMPOID{
		entire_encoding(8);
		$obj = OBJ_nid2obj(NID_time_stamp);
		printf("it's TIMESTAMPOID \n");};

ocspsignoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag OCSPSIGNOID{
		entire_encoding(8);
		$obj = OBJ_nid2obj(NID_OCSP_sign);
		printf("it's OCSPSIGNOID \n");};	
		

anyusageoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag ANYUSAGEOID{
		entire_encoding(4);
		$obj = OBJ_nid2obj(NID_anyExtendedKeyUsage);
		printf("it's ANYUSAGEOID \n");};
		
anypolicyoid returns [ASN1_OBJECT * obj]
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag ANYPOLICYOID{
		entire_encoding(4);
		$obj = OBJ_nid2obj(NID_any_policy);
		printf("it's ANYPOLICYOID \n");};
		
legacyemailoid returns [ASN1_OBJECT * obj] 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag LEGACYEMAILOID{
		entire_encoding(9);
		$obj = OBJ_nid2obj(NID_pkcs9_emailAddress);
		printf("It's legacy email oid \n");
	};

ecdhoid returns [ASN1_OBJECT * obj] 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag ECDHOID{
		entire_encoding(5);
		int new_nid = OBJ_txt2nid("1.3.132.1.12");
		if(new_nid == NID_undef)
			new_nid = OBJ_create("1.3.132.1.12","ECDH","ecdh_algorithm");
		$obj = OBJ_nid2obj(new_nid);
		printf("It's legacy email oid \n");
	};
	
ecmqvoid returns [ASN1_OBJECT * obj] 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	OIDTag ECMQVOID{
		entire_encoding(5);
		int new_nid = OBJ_txt2nid("1.3.132.1.13");
		if(new_nid == NID_undef)
			new_nid = OBJ_create("1.3.132.1.13","ECMQV","ecmqv_algorithm");
		$obj = OBJ_nid2obj(new_nid);
		printf("It's legacy email oid \n");
	};

printString returns [ASN1_PRINTABLESTRING* text]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	PrintStringTag printable {
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($PrintStringTag.text->chars,length);
	
		$text = (ASN1_PRINTABLESTRING *) new_asn1_string (19,mpz_get_ui(length),$printable.text);
	}
	;
	
ia5String returns [ASN1_IA5STRING* text]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	IA5StringTag printable {
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($IA5StringTag.text->chars,length);
		$text = (ASN1_IA5STRING *) new_asn1_string (22,mpz_get_ui(length),$printable.text);
	}
	;
	
utc returns [ASN1_TIME* text]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	UTCTag printable {
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($UTCTag.text->chars,length);
		//char pattern[20]="^[0-9]{12}Z\\z";
		char pattern[400]="(((0|2|4|6|8)(0|4|8)|(1|3|5|7|9)(2|6))((01|03|05|07|08|10|12)(0[1-9]|1[0-9]|2[0-9]|30|31)|(04|06|09|11)(0[1-9]|1[0-9]|2[0-9]|30)|02(0[1-9]|1[0-9]|2[0-9]))|((0|2|4|6|8)(1|2|3|5|6|7|9)|(1|3|5|7|9)(0|1|3|4|5|7|8|9))((01|03|05|07|08|10|12)(0[1-9]|1[0-9]|2[0-9]|30|31)|(04|06|09|11)(0[1-9]|1[0-9]|2[0-9]|30)|02(0[1-9]|1[0-9]|2[0-8])))(0[0-9]|1[0-9]|2[0-3])[0-5][0-9][0-5][0-9]Z$";
		if(check_string(pattern,$printable.text,mpz_get_ui(length)))
		{
			printf("Error in UTC \%s \n",$printable.text);
			exit(UTC_REGEXP_ERROR);
		}
		$text=malloc(sizeof(ASN1_TIME));
		$text->data = $printable.text;
		$text->length = mpz_get_ui(length);
		$text->type = 23;
		$text->flags = 0;
		printf("Time check is \%d \n",ASN1_TIME_check($text));
	}
	;
	
genTime returns [ASN1_TIME* text]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	GeneralTimeTag printable {
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($GeneralTimeTag.text->chars,length);
		//char pattern[20]="^[0-9]{14}Z\\z";
		char pattern[400]="^[0-9][0-9](((0|2|4|6|8)(0|4|8)|(1|3|5|7|9)(2|6))((01|03|05|07|08|10|12)(0[1-9]|1[0-9]|2[0-9]|30|31)|(04|06|09|11)(0[1-9]|1[0-9]|2[0-9]|30)|02(0[1-9]|1[0-9]|2[0-9]))|((0|2|4|6|8)(1|2|3|5|6|7|9)|(1|3|5|7|9)(0|1|3|4|5|7|8|9))((01|03|05|07|08|10|12)(0[1-9]|1[0-9]|2[0-9]|30|31)|(04|06|09|11)(0[1-9]|1[0-9]|2[0-9]|30)|02(0[1-9]|1[0-9]|2[0-8])))(0[0-9]|1[0-9]|2[0-3])[0-5][0-9][0-5][0-9]Z$";
		if(check_string(pattern,$printable.text,mpz_get_ui(length)))
		{
			printf("Error in Generalied Time \%s \n",$printable.text);
			exit(GENERALIZED_TIME_REGEXP_ERROR);
		}
		$text=malloc(sizeof(ASN1_TIME));
		$text->data = $printable.text;
		$text->length = mpz_get_ui(length);
		$text->type = 24;
		$text->flags = 0;
		printf("Time check is \%d \n",ASN1_TIME_check($text));
	};
	
	
truevalue 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TrueTag {
		entire_encoding(1);
		printf("True \n");
	}
	;
	
falsevalue	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	FalseTag {
		
		entire_encoding(1);
		printf("False \n");};

utf8String returns [ASN1_UTF8STRING* text]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	UTF8Tag printable {
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($UTF8Tag.text->chars,length);
		$text = (ASN1_UTF8STRING *) new_asn1_string (12,mpz_get_ui(length),$printable.text);
	}
	;
	

teletexString returns [ASN1_T61STRING* text]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TeletexTag printable {
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($TeletexTag.text->chars,length);
		$text = (ASN1_T61STRING *) new_asn1_string (20,mpz_get_ui(length),$printable.text);
	}
	;
	
bmpString returns [ASN1_BMPSTRING* text]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	BMPTag val {
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($BMPTag.text->chars,length);
		$text = (ASN1_BMPSTRING *) new_asn1_string (30,mpz_get_ui(length),$val.text);
	}
	;
	
univerString returns [ASN1_UNIVERSALSTRING* text]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	UniverStringTag printable {
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($UniverStringTag.text->chars,length);
		$text = (ASN1_UNIVERSALSTRING *) new_asn1_string (28,mpz_get_ui(length),$printable.text);
	}
	;
	
visibleString returns [ASN1_VISIBLESTRING* text]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	VisibleStringTag printable {
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($VisibleStringTag.text->chars,length);
		$text = (ASN1_VISIBLESTRING *) new_asn1_string (26,mpz_get_ui(length),$printable.text);
	}
	;
	
numericString returns[ASN1_STRING* text] @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	 NumericStringTag printable{
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($NumericStringTag.text->chars,length);
		$text = (ASN1_STRING *) new_asn1_string (18,mpz_get_ui(length),$printable.text);
	};
	
generalString returns[ASN1_STRING* text] @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	GeneralStringTag val{
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($GeneralStringTag.text->chars,length);
		$text = (ASN1_STRING *) new_asn1_string (27,mpz_get_ui(length),$val.text);
	};
	
graphicString returns[ASN1_STRING* text] @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	GraphicalStringTag val{
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($GraphicalStringTag.text->chars,length);
		$text = (ASN1_STRING *) new_asn1_string (25,mpz_get_ui(length),$val.text);
	};

videoString returns[ASN1_STRING* text] @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	VideoStringTag val{
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($VideoStringTag.text->chars,length);
		$text = (ASN1_STRING *) new_asn1_string (21,mpz_get_ui(length),$val.text);
	};

	
null 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	Null {entire_encoding(0);
		}
	;
	
sequenceTag 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	 SequenceTag
	{
		constructed_type($SequenceTag.text->chars);
	}
	;
	
set 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	SetTag
	{
		constructed_type($SetTag.text->chars);
	}
	;
	
constructedOctetString 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	ConstructedOctetTag 
	{
		constructed_type($ConstructedOctetTag.text->chars);
		printf("It's a constructed Octet String \n");
	}
	;
	
constructedBitString 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	ConstructedBitStringTag 
	{
		mpz_t length;
		mpz_init_set_ui(length,0);
		int len =compute_len($ConstructedBitStringTag.text->chars,length);
		mpz_sub_ui(length,length,1);
		push(length,len+1);
		printf("It's a constructed Bit String \n");
	}
	;  
	

constructedTag0 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	ConstructedTag0 {
		constructed_type($ConstructedTag0.text->chars);
		printf("it's tag0 constructed \n");};
tag0 returns [tag_type* text]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	@init{#ifdef DEBUG 
	push_rule(__func__); 
	#endif
	$text = malloc(sizeof(tag_type));}
	:
		onlyTag0{
		free($text);
		$text=$onlyTag0.text;
		}
		| 
		(tagInt1 {$text->value=malloc(1);$text->value[1]=1;}
		|tagInt2 {$text->value=malloc(1);$text->value[1]=2;}
		|tagInt3 {$text->value=malloc(1);$text->value[1]=3;}
		|tagInt4 {$text->value=malloc(1);$text->value[1]=4;}
		|tagInt5 {$text->value=malloc(1);$text->value[1]=5;}
		|tagInt6 {$text->value=malloc(1);$text->value[1]=6;}
		|tagInt7 {$text->value=malloc(1);$text->value[1]=7;}
		|tagInt8 {$text->value=malloc(1);$text->value[1]=8;}
		|tagInt9 {$text->value=malloc(1);$text->value[1]=9;}
		|tagInt10 {$text->value=malloc(1);$text->value[1]=10;}
		|tagInt11 {$text->value=malloc(1);$text->value[1]=11;}
		|tagInt12 {$text->value=malloc(1);$text->value[1]=12;}
		|tagInt13 {$text->value=malloc(1);$text->value[1]=13;}
		|tagInt14 {$text->value=malloc(1);$text->value[1]=14;}
		|tagInt15 {$text->value=malloc(1);$text->value[1]=15;}
		|tagInt16 {$text->value=malloc(1);$text->value[1]=16;}
		|tagInt17 {$text->value=malloc(1);$text->value[1]=17;}
		|tagInt18 {$text->value=malloc(1);$text->value[1]=18;}
		|tagInt19 {$text->value=malloc(1);$text->value[1]=19;}
		|tagInt20 {$text->value=malloc(1);$text->value[1]=20;}
		|tagInt21 {$text->value=malloc(1);$text->value[1]=21;}
		|tagInt22 {$text->value=malloc(1);$text->value[1]=22;}
		|tagInt23 {$text->value=malloc(1);$text->value[1]=23;}
		) 
		{
		$text->length = 1;
		}
	;
	
onlyTag0 returns[tag_type *text]
	:	Tag0 val{
		printf("it's tag0 \n");
		mpz_t length;
		mpz_init_set_ui(length,0);		
		primitive_type($Tag0.text->chars,length);
		$text=malloc(sizeof(tag_type));
		$text->value = $val.text;
		$text->length = mpz_get_ui(length);
		mpz_clear(length);
		};	

constructedTag1  	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	ConstructedTag1 {
		constructed_type($ConstructedTag1.text->chars);
		printf("it's tag1 constructed \n");};
tag1 returns [tag_type* text]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	Tag1  val {
		printf("it's tag1 \n");
		mpz_t length;
		mpz_init_set_ui(length,0);		
		primitive_type($Tag1.text->chars,length);
		tag_type *tag = malloc(sizeof(tag_type));
		tag->value = $val.text;
		tag->length = mpz_get_ui(length);
		mpz_clear(length);
		$text = tag ;}
	;
	
/*tag1Printable returns [tag_type* text] @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	 Tag1 printable{
		printf("it's tag1 printable \n");	
		mpz_t length;
		mpz_init_set_ui(length,0);	
		primitive_type($Tag1.text->chars,length);
		tag_type *tag = malloc(sizeof(tag_type));
		tag->value = $printable.text;
		tag->length = mpz_get_ui(length);
		mpz_clear(length);
		$text = tag ;}
	;*/
	
appTag1 @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	AppTag1 {
	constructed_type($AppTag1.text->chars);
	};
	
appTag2 @after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	AppTag2{
	constructed_type($AppTag2.text->chars);
	};
	

constructedTag2 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	ConstructedTag2 {
		constructed_type($ConstructedTag2.text->chars);
		printf("it's tag2 constructed \n");};
tag2 returns [tag_type* text]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	Tag2  val {
		printf("it's tag2 \n");
		mpz_t length;
		mpz_init_set_ui(length,0);		
		primitive_type($Tag2.text->chars,length);
		tag_type *tag = malloc(sizeof(tag_type));
		tag->value = $val.text;
		tag->length = mpz_get_ui(length);
		mpz_clear(length);
		$text = tag ;}
	;
/*tag2Printable returns [tag_type* text] 
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	Tag2 printable{
		printf("it's tag2 printable \n");	
		mpz_t length;
		mpz_init_set_ui(length,0);	
		primitive_type($Tag2.text->chars,length);
		tag_type *tag = malloc(sizeof(tag_type));
		tag->value = $printable.text;
		tag->length = mpz_get_ui(length);
		mpz_clear(length);
		$text = tag ;}	
	;*/


constructedTag3 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	ConstructedTag3 {
		constructed_type($ConstructedTag3.text->chars);
		printf("it's tag3 constructed \n");};
tag3 returns [tag_type* text]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	Tag3  val {
		printf("it's tag3 \n");	
		mpz_t length;
		mpz_init_set_ui(length,0);	
		primitive_type($Tag3.text->chars,length);
		tag_type *tag = malloc(sizeof(tag_type));
		tag->value = $val.text;
		tag->length = mpz_get_ui(length);
		mpz_clear(length);
		$text = tag ;}
	;
	

constructedTag4 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	ConstructedTag4 {
		constructed_type($ConstructedTag4.text->chars);
		printf("it's tag4 constructed \n");};
tag4 returns [tag_type* text]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	Tag4  val {
		printf("it's tag4 \n");		
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($Tag4.text->chars,length);
		tag_type *tag = malloc(sizeof(tag_type));
		tag->value = $val.text;
		tag->length = mpz_get_ui(length);
		mpz_clear(length);
		$text = tag ;}
	;
	

constructedTag5 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	ConstructedTag5 {
		constructed_type($ConstructedTag5.text->chars);
		printf("it's tag5 constructed \n");};
tag5 returns [tag_type* text]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	Tag5  val {
		printf("it's tag5 \n");		
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($Tag5.text->chars,length);
		tag_type *tag = malloc(sizeof(tag_type));
		tag->value = $val.text;
		tag->length = mpz_get_ui(length);
		mpz_clear(length);
		$text = tag ;}
	;
	

constructedTag6 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	ConstructedTag6 {
		constructed_type($ConstructedTag6.text->chars);
		printf("it's tag6 constructed \n");};
tag6 returns [tag_type* text]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	Tag6  val {
		printf("it's tag6 \n");		
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($Tag6.text->chars,length);
		tag_type *tag = malloc(sizeof(tag_type));
		tag->value = $val.text;
		tag->length = mpz_get_ui(length);
		mpz_clear(length);
		$text = tag ;}
	;
	

constructedTag7 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	ConstructedTag7 {
		constructed_type($ConstructedTag7.text->chars);
		printf("it's tag7 constructed \n");};		
tag7 returns [tag_type* text]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	Tag7  val {
		printf("it's tag7 \n");		
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($Tag7.text->chars,length);
		tag_type *tag = malloc(sizeof(tag_type));
		tag->value = $val.text;
		tag->length = mpz_get_ui(length);
		mpz_clear(length);
		$text = tag ;}
	;
	

constructedTag8 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	ConstructedTag8 {
		constructed_type($ConstructedTag8.text->chars);
		printf("it's tag8 constructed \n");};
tag8 returns [tag_type* text]	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	Tag8  val {
		printf("it's tag8 \n");
		mpz_t length;
		mpz_init_set_ui(length,0);
		primitive_type($Tag8.text->chars,length);
		tag_type *tag = malloc(sizeof(tag_type));
		tag->value = $val.text;
		tag->length = mpz_get_ui(length);
		mpz_clear(length);
		$text = tag ;}
	;
	
tagInt1 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TagInt1 {entire_encoding(1);};
tagInt2 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TagInt2 {entire_encoding(1);};
tagInt3 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TagInt3 {entire_encoding(1);};
tagInt4 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TagInt4 {entire_encoding(1);};
tagInt5 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TagInt5 {entire_encoding(1);};
tagInt6 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TagInt6 {entire_encoding(1);};
tagInt7 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TagInt7 {entire_encoding(1);};
tagInt8 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TagInt8 {entire_encoding(1);};
tagInt9 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TagInt9 {entire_encoding(1);};
tagInt10 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TagInt10 {entire_encoding(1);};
tagInt11 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TagInt11 {entire_encoding(1);};
tagInt12 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TagInt12 {entire_encoding(1);};
tagInt13 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TagInt13 {entire_encoding(1);};
tagInt14 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TagInt14 {entire_encoding(1);};
tagInt15 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TagInt15 {entire_encoding(1);};
tagInt16 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TagInt16 {entire_encoding(1);};
tagInt17 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TagInt17 {entire_encoding(1);};
tagInt18 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TagInt18 {entire_encoding(1);};
tagInt19 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TagInt19 {entire_encoding(1);};
tagInt20 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TagInt20 {entire_encoding(1);};
tagInt21 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TagInt21 {entire_encoding(1);};
tagInt22 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TagInt22 {entire_encoding(1);};
tagInt23 	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
	:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	TagInt23 {entire_encoding(1);};
/*val returns [char* text]	: {counter_primitive>0}?	value=. {counter_primitive -= strlen($value.text->chars);} v=val {
	$text = malloc(strlen($v.text)+strlen($value.text->chars)+1);
	strcpy($text,$value.text->chars);
	strcat($text,$v.text);
	}| {counter_primitive == 0}? {$text=malloc(1);strcpy($text,"");}
	/*value=. {$text = malloc(2);
	strcpy($text,$value.text->chars);
	//counter_primitive--;
	}
	;*/


/*val returns [char* text]	:	Val
		{
			$text = $Val.text->chars;
		};

printable returns [char* text]	:	Printable		
		{
			$text = $Printable.text->chars;
		};

onlyval returns [char *text] 	:	OnlyVal
		{
			$text = $OnlyVal.text->chars;
		};*/
	
printable returns [char* text]	@init{int i=0;char *s = malloc(16);}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}
		:{#ifdef DEBUG 
	push_rule(__func__); 
	#endif}	(PRINTABLE{i=store_value($PRINTABLE.text->chars,i,&s,$PRINTABLE.text->len);
		})+
		{s[i]=0;$text=s;printf("it's printable \%s \n",$text);};
		
	
val returns [char* text]	@init{int i=0;char *s = malloc(16);
	#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}:
	{printf("It's val \n");}	(VALUE{i=store_value($VALUE.text->chars,i,&s,$VALUE.text->len);}
	|PRINTABLE{i=store_value($PRINTABLE.text->chars,i,&s,$PRINTABLE.text->len);})+ {s[i]=0;$text=s;printf("Val lexed \%s \n",$text);}
		//|Val  {$text=$Val.text->chars;}
		;


/*onlyval returns [char* text]	@init{int i=0;char *s = malloc(16);
	#ifdef DEBUG 
	push_rule(__func__); 
	#endif}
	@after{#ifdef DEBUG
	pop_rule(); 
	#endif}:
		(VALUE{i=store_value($VALUE.text->chars,i,&s,$VALUE.text->len);})+
		{s[i]=0;$text=s;printf("it's onlyval \%s \n",$text);}
		|Val {$text=$Val.text->chars;}
		;	
/*IDBIN 	:	',' IDBIN ',' 
	|	'_' (TOKEN5 {printf("5 \n");} | TOKEN6 {printf("\%d \n",$TOKEN6.text->chars[0]);})*/
	
/*Val 	:	{counter_primitive>0 && tag}?=> {printf("i'm in Val \%d \n",tag);} (PRINTABLE+  ( {counter_primitive == 0}?=> {LEXSTATE->type=PRINTABLE;tag=0;goto ruleValEx;}|{counter_primitive>0}?=>VALUE+ {tag=0;} ) 
		|VALUE+ {tag=0;});*/
	
OctetTag 	:	  {counter_primitive==0 && !constructed_octet}?=> '\u0004' LENGTH  {counter_primitive = compute_length($LENGTH.text->chars);};//{$value = 7; printf("length is \%d \n",$LENGTH.text->chars[0]);};

ConstructedOctetTag 
	:	 {counter_primitive==0 && constructed_octet}?=> '\u0004' LENGTH {printf("constructed octet \n");constructed_octet=0;};

IntTag	:	 {counter_primitive==0}?=> '\u0002' LENGTH {counter_primitive = compute_length($LENGTH.text->chars);};

BitStringTag	:	 {counter_primitive==0 && !constructed_bit}?=> '\u0003' LENGTH {counter_primitive = compute_length($LENGTH.text->chars);key_usage = 0;};

ConstructedBitStringTag 
	:	{counter_primitive==0 && constructed_bit}?=> '\u0003' LENGTH '\u0000'{printf("constructed but \n");constructed_bit = 0;};
	
BitStringKeyCert 
	:	{counter_primitive==0 && key_usage}?=>'\u0003' ( '\u0002' '\u0003'..'\u0007' {counter_primitive=1;}|('\u0002' '\u0000'..'\u0002' {counter_primitive = 1;} | '\u0003' '\u0007' {counter_primitive = 2;}) 
		(('\u000C'..'\u000F' | '\u001C'..'\u001F' | '\u002C'..'\u002F' | '\u003C'..'\u003F' | '\u004C'..'\u004F' | '\u005C'..'\u005F' | '\u006C'..'\u006F'
		| '\u007C'..'\u007F'| '\u008C'..'\u008F'| '\u009C'..'\u009F'| '\u00AC'..'\u00AF'| '\u00BC'..'\u00BF'| '\u00CC'..'\u00CF'| '\u00DC'..'\u00DF'| '\u00EC'..'\u00EF'
		| '\u00FC'..'\u00FF'| '\u00F4'..'\u00F7'| '\u00E4'..'\u00E7'| '\u00D4'..'\u00D7'| '\u00C4'..'\u00C7'| '\u00B4'..'\u00B7'| '\u00A4'..'\u00A7'
		| '\u0094'..'\u0097'| '\u0084'..'\u0087'| '\u0074'..'\u0077'| '\u0064'..'\u0067'| '\u0054'..'\u0057'| '\u0044'..'\u0047'| '\u0034'..'\u0037'
		| '\u0024'..'\u0027'| '\u0014'..'\u0017'| '\u0004'..'\u0007'){counter_primitive--;} ({counter_primitive == 0}?=> |{counter_primitive>0}?=>
		('\u0080' {counter_primitive--;}
		|'\u0000'..'\u007F' {exit(CERT_SIGN_ASN1_ENCODING_ERROR);}
		|'\u0081'..'\u00FF' {exit(CERT_SIGN_ASN1_ENCODING_ERROR);})))?)  {key_usage = 0;};

PrintStringTag:	  {counter_primitive==0}?=>'\u0013' LENGTH {counter_primitive = compute_length($LENGTH.text->chars);};

OIDTag	:	  {counter_primitive==0}?=>'\u0006' LENGTH {counter_primitive = compute_length($LENGTH.text->chars);oid = 1;printf("OID is \%d and counter is \%d \n",oid,counter_primitive);};

IA5StringTag	:	  {counter_primitive==0}?=>'\u0016' LENGTH {counter_primitive = compute_length($LENGTH.text->chars);};

UTCTag	:	 {counter_primitive==0}?=> '\u0017' LENGTH {counter_primitive = compute_length($LENGTH.text->chars);};

TrueTag 	:	{counter_primitive==0}?=>'\u0001' '\u0001' '\u0001'..'\u00FF';

FalseTag 	:	{counter_primitive==0}?=>'\u0001' '\u0001' '\u0000';

UTF8Tag	:	  {counter_primitive==0}?=>'\u000C' LENGTH {counter_primitive = compute_length($LENGTH.text->chars);};

TeletexTag	:	  {counter_primitive==0}?=>'\u0014' LENGTH {counter_primitive = compute_length($LENGTH.text->chars);};

BMPTag	:	  {counter_primitive==0}?=>'\u001E' LENGTH {counter_primitive = compute_length($LENGTH.text->chars);};

UniverStringTag	:	  {counter_primitive==0}?=>'\u001C' LENGTH {counter_primitive = compute_length($LENGTH.text->chars);};

GeneralTimeTag	:	  {counter_primitive==0}?=>'\u0018' LENGTH {counter_primitive = compute_length($LENGTH.text->chars);};

VisibleStringTag	:	  {counter_primitive==0}?=>'\u001A' LENGTH {counter_primitive = compute_length($LENGTH.text->chars);};

NumericStringTag	:	  {counter_primitive==0}?=>'\u0012' LENGTH {counter_primitive = compute_length($LENGTH.text->chars);};

GeneralStringTag	:	  {counter_primitive==0}?=>'\u001B' LENGTH {counter_primitive = compute_length($LENGTH.text->chars);};

GraphicalStringTag	:	  {counter_primitive==0}?=>'\u0019' LENGTH {counter_primitive = compute_length($LENGTH.text->chars);};

VideoStringTag	:	  {counter_primitive==0}?=>'\u0015' LENGTH {counter_primitive = compute_length($LENGTH.text->chars);};


SequenceTag 
	:	  {counter_primitive==0}?=>'\u0030' LENGTH {printf("sequence \n");};
	
SetTag	:	  {counter_primitive==0}?=>'\u0031' LENGTH;

ConstructedTag0 
	:	 {counter_primitive==0}?=>'\u00a0' LENGTH ;
	
Tag0 	:	 {counter_primitive==0}?=>'\u0080' LENGTH  {counter_primitive = compute_length($LENGTH.text->chars);};

ConstructedTag1 
	:	 {counter_primitive==0}?=>'\u00a1' LENGTH ;
	
Tag1 	:	 {counter_primitive==0}?=>'\u0081' LENGTH  {counter_primitive = compute_length($LENGTH.text->chars);};

ConstructedTag2 
	:	 {counter_primitive==0}?=>'\u00a2' LENGTH ;
	
Tag2 	:	 {counter_primitive==0}?=>'\u0082' LENGTH  {counter_primitive = compute_length($LENGTH.text->chars);};

ConstructedTag3 
	:	 {counter_primitive==0}?=>'\u00a3' LENGTH {printf("Tag a3 \n");};
	
Tag3 	:	 {counter_primitive==0}?=>'\u0083' LENGTH  {counter_primitive = compute_length($LENGTH.text->chars);};

ConstructedTag4 
	:	 {counter_primitive==0}?=>'\u00a4' LENGTH ;
	
Tag4 	:	 {counter_primitive==0}?=>'\u0084' LENGTH  {counter_primitive = compute_length($LENGTH.text->chars);};

ConstructedTag5 
	:	 {counter_primitive==0}?=>'\u00a5' LENGTH ;
	
Tag5 	:	 {counter_primitive==0}?=>'\u0085' LENGTH  {counter_primitive = compute_length($LENGTH.text->chars);};

ConstructedTag6 
	:	 {counter_primitive==0}?=>'\u00a6' LENGTH ;
	
Tag6 	:	 {counter_primitive==0}?=>'\u0086' LENGTH  {counter_primitive = compute_length($LENGTH.text->chars);};

ConstructedTag7 
	:	 {counter_primitive==0}?=>'\u00a7' LENGTH ;
	
Tag7	:	 {counter_primitive==0}?=>'\u0087' LENGTH  {counter_primitive = compute_length($LENGTH.text->chars);};

ConstructedTag8 
	:	 {counter_primitive==0}?=>'\u00a8' LENGTH ;
	
Tag8 	:	 {counter_primitive==0}?=>'\u0088' LENGTH  {counter_primitive = compute_length($LENGTH.text->chars);};

AppTag1 	:	{counter_primitive==0}?=>'\u0061' LENGTH;

AppTag2 	:	{counter_primitive==0}?=>'\u0062' LENGTH;

Int0 	:	{counter_primitive==0}?=>'\u0002' '\u0001' '\u0000';

Int1 	:	{counter_primitive==0}?=>'\u0002' '\u0001' '\u0001';

Int2 	:	{counter_primitive==0}?=>'\u0002' '\u0001' '\u0002';

Null 	:	{counter_primitive==0}?=>'\u0005' '\u0000' {printf("Null parsed \n");};

TagInt1 	:	{counter_primitive==0}?=>'\u0080' '\u0001' '\u0001';

TagInt2 	:	{counter_primitive==0}?=>'\u0080' '\u0001' '\u0002';

TagInt3 	:	{counter_primitive==0}?=>'\u0080' '\u0001' '\u0003';

TagInt4 	:	{counter_primitive==0}?=>'\u0080' '\u0001' '\u0004';

TagInt5 	:	{counter_primitive==0}?=>'\u0080' '\u0001' '\u0005';

TagInt6 	:	{counter_primitive==0}?=>'\u0080' '\u0001' '\u0006';

TagInt7 	:	{counter_primitive==0}?=>'\u0080' '\u0001' '\u0007';

TagInt8 	:	{counter_primitive==0}?=>'\u0080' '\u0001' '\u0008';

TagInt9 	:	{counter_primitive==0}?=>'\u0080' '\u0001' '\u0009';

TagInt10 	:	{counter_primitive==0}?=>'\u0080' '\u0001' '\u000A';

TagInt11 	:	{counter_primitive==0}?=>'\u0080' '\u0001' '\u000B';

TagInt12 	:	{counter_primitive==0}?=>'\u0080' '\u0001' '\u000C';

TagInt13	:	{counter_primitive==0}?=>'\u0080' '\u0001' '\u000D';

TagInt14 	:	{counter_primitive==0}?=>'\u0080' '\u0001' '\u000E';

TagInt15 	:	{counter_primitive==0}?=>'\u0080' '\u0001' '\u000F';

TagInt16 	:	{counter_primitive==0}?=>'\u0080' '\u0001' '\u0010';

TagInt17 	:	{counter_primitive==0}?=>'\u0080' '\u0001' '\u0011';

TagInt18 	:	{counter_primitive==0}?=>'\u0080' '\u0001' '\u0012';

TagInt19 	:	{counter_primitive==0}?=>'\u0080' '\u0001' '\u0013';

TagInt20 	:	{counter_primitive==0}?=>'\u0080' '\u0001' '\u0014';

TagInt21 	:	{counter_primitive==0}?=>'\u0080' '\u0001' '\u0015';

TagInt22 	:	{counter_primitive==0}?=>'\u0080' '\u0001' '\u0016';

TagInt23 	:	{counter_primitive==0}?=>'\u0080' '\u0001' '\u0017';


fragment LENGTH 	:	'\u0000'..'\u007F' 
| '\u0081'  '\u0080'..'\u00FF'
| '\u0082'  VAL2
| '\u0083'  VAL2 VAL
| '\u0084'  (VAL4 | '\u0080'..'\u00FF' {exit(61);})
/*| '\u0085'  VAL4 VAL
| '\u0086'  VAL4 VAL2
| '\u0087'  VAL4 VAL2 VAL
| '\u0088'  VAL4 VAL4
/*| '\u0089'  VAL VAL VAL VAL VAL VAL VAL VAL VAL
| '\u008A'  VAL VAL VAL VAL VAL VAL VAL VAL VAL VAL
| '\u008B'  VAL VAL VAL VAL VAL VAL VAL VAL VAL VAL VAL
| '\u008C'  VAL VAL VAL VAL VAL VAL VAL VAL VAL VAL VAL VAL
| '\u008D'  VAL VAL VAL VAL VAL VAL VAL VAL VAL VAL VAL VAL VAL
| '\u008E'  VAL VAL VAL VAL VAL VAL VAL VAL VAL VAL VAL VAL VAL VAL
| '\u008F'  VAL VAL VAL VAL VAL VAL VAL VAL VAL VAL VAL VAL VAL VAL VAL*/
		;


		

EXTSOID :	{(counter_primitive == 3 || counter_primitive == 4)&& oid}?=> ('\u0055' ('\u001D' 
	('\u0023' {LEXSTATE->type = OIDAKI;constructed_octet=1;}
	|'\u000E' {LEXSTATE->type = OIDSKI;constructed_octet=1;}
	|'\u000F' {LEXSTATE->type = OIDKEYUS;constructed_octet=1;key_usage=1;}
	|'\u0020' 		
		({counter_primitive == 3}?=> {LEXSTATE->type = OIDCERTPOL;constructed_octet=1;}
		|{counter_primitive != 3}?=> '\u0000' {LEXSTATE->type = ANYPOLICYOID;counter_primitive--;}
		|{counter_primitive != 3}?=> '\u0001'..'\u00FF' {oid=0;LEXSTATE->type = VALUE;counter_primitive--;}
		)
	|'\u0021' {LEXSTATE->type = OIDPOLMAP;constructed_octet=1;}
	|'\u0011' {LEXSTATE->type = OIDSUBALT;constructed_octet=1;}
	|'\u0012' {LEXSTATE->type = OIDISSALT;constructed_octet=1;}
	|'\u0009' {LEXSTATE->type = OIDSUBDIR;constructed_octet=1;}
	|'\u0024' {LEXSTATE->type = OIDPOLCONST;constructed_octet=1;}
	|'\u0025'
		({counter_primitive == 3}?=> {LEXSTATE->type = OIDEXTKEY;constructed_octet=1;}
		|{counter_primitive != 3}?=> '\u0000' {LEXSTATE->type = ANYUSAGEOID;counter_primitive--;}
		|{counter_primitive != 3}?=> '\u0001'..'\u00FF' {oid=0;LEXSTATE->type = VALUE;counter_primitive--;}
		)
	|'\u001F' {LEXSTATE->type = OIDCRL;constructed_octet=1;}
	|'\u0036' {LEXSTATE->type = OIDINHIBIT;constructed_octet=1;}
	|'\u001E' {LEXSTATE->type = OIDNAME;constructed_octet=1;}
	|'\u0013' {LEXSTATE->type = OIDBC;constructed_octet=1;}
	|'\u002E' {LEXSTATE->type = OIDFRESHCRL;constructed_octet=1;}
	|('\u0000'..'\u0008' | '\u000A'..'\u000D'
	|'\u0010' |'\u0014'..'\u001D' |'\u0022'|'\u0026'..'\u002D'|'\u002F'..'\u0035'|'\u0037'..'\u00FF')  {oid=0;LEXSTATE->type = VALUE;}
	) {counter_primitive -=3;oid=0;goto ruleEXTSOIDEx;}
	|( '\u0000'..'\u001C' |'\u001E'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=2;goto ruleEXTSOIDEx;})|( '\u0000'..'\u0054'|'\u0056'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive--;goto ruleEXTSOIDEx;});

/*OIDRADIX 
	:	{counter_primitive==3 && oid}?=> '\u0055'{counter_primitive--;};
	
OIDDN 	:	{counter_primitive==2 && oid}?=>'\u0004'{counter_primitive--;};

OIDCN 	:	{counter_primitive==1 && oid}?=>'\u0003'{counter_primitive--;oid=0;};*/
DNOID 	:	{counter_primitive == 3 && oid}?=> ('\u0055' ('\u0004' {counter_primitive-=3;oid=0;}
	('\u0003' {LEXSTATE->type = OIDCN;goto ruleDNOIDEx;}
	|'\u000A' {LEXSTATE->type = OIDON;goto ruleDNOIDEx;}
	|'\u0029' {LEXSTATE->type = NAMEOID;goto ruleDNOIDEx;}
	|'\u0004' {LEXSTATE->type = SURNAMEOID;goto ruleDNOIDEx;}
	|'\u002A' {LEXSTATE->type = OIDGIVENAME;goto ruleDNOIDEx;}
	|'\u002B' {LEXSTATE->type = OIDINIT;goto ruleDNOIDEx;}
	|'\u002C' {LEXSTATE->type = OIDGENQUALIFIER;goto ruleDNOIDEx;}
	|'\u0007' {LEXSTATE->type = OIDLOCAL;goto ruleDNOIDEx;}
	|'\u0008' {LEXSTATE->type = OIDSORP;goto ruleDNOIDEx;}
	|'\u000B' {LEXSTATE->type = OIDOU;goto ruleDNOIDEx;}
	|'\u000C' {LEXSTATE->type = OIDTITLE;goto ruleDNOIDEx;}
	|'\u002E' {LEXSTATE->type = OIDDNQUALIFIER;goto ruleDNOIDEx;}
	|'\u0006' {LEXSTATE->type = OIDCOUNTRY;goto ruleDNOIDEx;}
	|'\u0005' {LEXSTATE->type = OIDSERIAL;goto ruleDNOIDEx;}
	|'\u0041' {LEXSTATE->type = OIDPSEUDO;goto ruleDNOIDEx;}
	|('\u0001'|'\u0002'|'\u0009'|'\u000D'..'\u0028'|'\u002D'|'\u002F'..'\u0040'|'\u0042'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;goto ruleDNOIDEx;}
	) 
	| ('\u0000'..'\u0003'|'\u0005'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=2;goto ruleDNOIDEx;} ) |( '\u0000'..'\u0054'|'\u0056'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive--;goto ruleDNOIDEx;});
	
PRIVATEEXTSOID 
	:	{counter_primitive == 8 && oid}?=>('\u002B' ('\u0006' ('\u0001' ('\u0005' ('\u0005' ('\u0007' 
	('\u0001' 
		('\u0001' {LEXSTATE->type=AIAOID;constructed_octet=1;}
		|'\u000B' {LEXSTATE->type=SIAOID;constructed_octet=1;}
		|('\u0000'|'\u0002'..'\u000A'|'\u000C'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;}
		){counter_primitive -=8;oid=0;goto rulePRIVATEEXTSOIDEx;}
	|'\u0030'
		('\u0001' {LEXSTATE->type=OCSPOID;}
		|'\u0002' {LEXSTATE->type=CAISSUEROID;}
		|'\u0003' {LEXSTATE->type=TSPOID;}
		|'\u0005' {LEXSTATE->type=CAREPOOID;}
		| ('\u0000' | '\u0004' |'\u0006'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;}
		){counter_primitive -=8;oid=0;goto rulePRIVATEEXTSOIDEx;}	
	|'\u0002' 
		('\u0001' {LEXSTATE->type=CPSOID;}
		|'\u0002' {LEXSTATE->type=UNOTICEOID;}
		|('\u0000'|'\u0003'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;}
		){counter_primitive -=8;oid=0;goto rulePRIVATEEXTSOIDEx;}
	|'\u0003' 
		('\u0001' {LEXSTATE->type=SERVERAUTHOID;}
		|'\u0002' {LEXSTATE->type=CLIENTAUTHOID;}
		|'\u0003' {LEXSTATE->type=CODESIGNOID;}
		|'\u0004' {LEXSTATE->type=EMAILPROTECTOID;}
		|'\u0008' {LEXSTATE->type=TIMESTAMPOID;}
		|'\u0009' {LEXSTATE->type=OCSPSIGNOID;}
		|('\u0000'|'\u0005'..'\u0007'|'\u000A'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;}
		){counter_primitive -=8;oid=0;goto rulePRIVATEEXTSOIDEx;}	
	| ('\u0000'|'\u0004'..'\u002F'|'\u0031'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=7;goto rulePRIVATEEXTSOIDEx;}
	)|( '\u0000'..'\u0006' | '\u0008'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=6;goto rulePRIVATEEXTSOIDEx;})| ('\u0000'..'\u0004'|'\u0006'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=5;goto rulePRIVATEEXTSOIDEx;})| ('\u0000'..'\u0004' | '\u0006'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=4;goto rulePRIVATEEXTSOIDEx;})| ('\u0000'|'\u0002'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=3;goto rulePRIVATEEXTSOIDEx;})|( '\u0000'..'\u0005' | '\u0007'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=2;goto rulePRIVATEEXTSOIDEx;}) |( '\u0000'..'\u002A' | '\u002C'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive--;goto rulePRIVATEEXTSOIDEx;}
	);
	

RSAOID 	:	{counter_primitive == 9 && oid}?=> ('\u002A' ('\u0086' ('\u0048' ('\u0086' ('\u00F7' ('\u000D' ('\u0001' 
	('\u0001' 
		('\u0001' {LEXSTATE->type=RSAPKOID;pss_constructed_bit_flag=1-pss_constructed_bit_flag;constructed_bit=1;}
		|'\u0008' {LEXSTATE->type=MGF1OID;}
		|'\u000A' {LEXSTATE->type=RSAPSSOID;pss_constructed_bit_flag=1-pss_constructed_bit_flag;constructed_bit=pss_constructed_bit_flag;printf("bit flag is \%d \n",pss_constructed_bit_flag);}
		|'\u0007' {LEXSTATE->type=RSAOAEPOID;pss_constructed_bit_flag=1-pss_constructed_bit_flag;constructed_bit=1;}
		|'\u0009' {LEXSTATE->type=PSPECOID;}
		|'\u0002' {LEXSTATE->type=MD2RSAOID;pss_constructed_bit_flag=1-pss_constructed_bit_flag;}
		|'\u0004' {LEXSTATE->type=MD5RSAOID;pss_constructed_bit_flag=1-pss_constructed_bit_flag;}
		|'\u0005' {LEXSTATE->type=SHA1RSAOID;pss_constructed_bit_flag=1-pss_constructed_bit_flag;}
		|'\u000E' {LEXSTATE->type=SHA224RSAOID;pss_constructed_bit_flag=1-pss_constructed_bit_flag;}
		|'\u000B' {LEXSTATE->type=SHA256RSAOID;pss_constructed_bit_flag=1-pss_constructed_bit_flag;}
		|'\u000C' {LEXSTATE->type=SHA384RSAOID;pss_constructed_bit_flag=1-pss_constructed_bit_flag;}
		|'\u000D' {LEXSTATE->type=SHA512RSAOID;pss_constructed_bit_flag=1-pss_constructed_bit_flag;}
		|('\u0000' | '\u0003' | '\u0006'|'\u000F'..'\u00FF') {LEXSTATE->type = VALUE;}
		){counter_primitive -=9;oid=0;goto ruleRSAOIDEx;}
	|'\u0009'
		('\u0001' {LEXSTATE->type=LEGACYEMAILOID;}
		|('\u0000' | '\u0002'..'\u00FF') {LEXSTATE->type = VALUE;}
		){counter_primitive -=9;oid=0;goto ruleRSAOIDEx;}
	|( '\u0000'|'\u0002'..'\u0008'|'\u000A'..'\u00FF'){oid=0;LEXSTATE->type = VALUE;counter_primitive-=8;goto ruleRSAOIDEx;})| ('\u0000'|'\u0002'..'\u00FF'){oid=0;LEXSTATE->type = VALUE;counter_primitive-=7;goto ruleRSAOIDEx;})|('\u0000'..'\u000C'|'\u000E'..'\u00FF'){oid=0;LEXSTATE->type = VALUE;counter_primitive-=6;goto ruleRSAOIDEx;})| ('\u0000'..'\u00F6'|'\u00F8'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=5;goto ruleRSAOIDEx;})| ('\u0000'..'\u0085' | '\u0087'..'\u00FF'){oid=0;LEXSTATE->type = VALUE;counter_primitive-=4;goto ruleRSAOIDEx;})|( '\u0000'..'\u0047' | '\u0049'..'\u00FF'){oid=0;LEXSTATE->type = VALUE;counter_primitive-=3;goto ruleRSAOIDEx;})| ('\u0000'..'\u0085' | '\u0087'..'\u00FF'){oid=0;LEXSTATE->type = VALUE;counter_primitive-=2;goto ruleRSAOIDEx;}) |( '\u0000'..'\u0029' | '\u002B'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive--;goto ruleRSAOIDEx;}
	);
	
ECOID 	:{(counter_primitive ==9 || counter_primitive==8 ||counter_primitive == 7) && oid}?=> ('\u002A' ('\u0086' ('\u0048' ('\u00CE' ('\u003D' 
	('\u0001' 
		('\u0001' {LEXSTATE->type=PRIMEOID;counter_primitive-=7;oid=0;goto ruleECOIDEx;}
		|'\u0002' {counter_primitive-=7;}
			({counter_primitive == 0}?=> {LEXSTATE->type=BASIS2OID;oid=0;goto ruleECOIDEx;}
			|{counter_primitive != 0}?=> '\u0001'
				('\u0001' {LEXSTATE->type=GNBASISOID;}
				|'\u0002' {LEXSTATE->type=TPBASISOID;}
				|'\u0003' {LEXSTATE->type=PPBASISOID;}
				|('\u0000' | '\u0004'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;}
				){counter_primitive-=2;oid=0;goto ruleECOIDEx;}
			|{counter_primitive != 0}?=> ('\u0000' | '\u0002'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive--;goto ruleECOIDEx;}
			)
		|('\u0000' | '\u0003'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=7;goto ruleECOIDEx;}
		)
	| '\u0002'
		('\u0001' {LEXSTATE->type=ECPKOID;pss_constructed_bit_flag=1-pss_constructed_bit_flag;}
		|'\u0000'| '\u0002'..'\u00FF' {oid=0;LEXSTATE->type = VALUE;}
		) {counter_primitive-=7;oid=0;goto ruleECOIDEx;}
	|'\u0004'
		('\u0001' {counter_primitive-=7;LEXSTATE->type=SHA1ECOID;oid=0;pss_constructed_bit_flag=1-pss_constructed_bit_flag;ecdsa_counter++;constructed_bit+=ecdsa_counter;goto ruleECOIDEx;} 
		|'\u0003' 
			('\u0001' {LEXSTATE->type=SHA224ECOID;pss_constructed_bit_flag=1-pss_constructed_bit_flag;ecdsa_counter++;constructed_bit+=ecdsa_counter;}
			|'\u0002' {LEXSTATE->type=SHA256ECOID;pss_constructed_bit_flag=1-pss_constructed_bit_flag;ecdsa_counter++;constructed_bit+=ecdsa_counter;{printf("ECSHA256OID \n");}}
			|'\u0003' {LEXSTATE->type=SHA384ECOID;pss_constructed_bit_flag=1-pss_constructed_bit_flag;ecdsa_counter++;constructed_bit+=ecdsa_counter;}
			|'\u0004' {LEXSTATE->type=SHA512ECOID;pss_constructed_bit_flag=1-pss_constructed_bit_flag;ecdsa_counter++;constructed_bit+=ecdsa_counter;}
			|('\u0000' | '\u0005'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;}
			){counter_primitive-=8;oid=0;goto ruleECOIDEx;}
		|('\u0000'|'\u0002' | '\u0004'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=7;goto ruleECOIDEx;}
		)
	|('\u0000'|'\u0003' | '\u0005'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=6;goto ruleECOIDEx;}
	)
	| ('\u0000'..'\u003C' | '\u003E'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=5;goto ruleECOIDEx;})| ('\u0000'..'\u00CD' | '\u00CF'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=4;goto ruleECOIDEx;})| ('\u0000'..'\u0047' | '\u0049'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=3;goto ruleECOIDEx;})| ('\u0000'..'\u0085' | '\u0087'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=2;goto ruleECOIDEx;})| ('\u0000'..'\u0029' | '\u002B'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive--;
		goto ruleECOIDEx;});
		
HASHOID :	{counter_primitive == 9 && oid}?=> ('\u0060' ('\u0086' ('\u0048' ('\u0001' ('\u0065' 
	('\u0003' 
		('\u0004'
			('\u0002'
				('\u0001' {LEXSTATE->type=SHA256OID;}
				|'\u0002' {LEXSTATE->type=SHA384OID;}
				|'\u0003' {LEXSTATE->type=SHA512OID;}
				|'\u0004' {LEXSTATE->type=SHA224OID;}
				|('\u0000' | '\u0005'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;}
				){counter_primitive-=9;oid=0;goto ruleHASHOIDEx;}
			|'\u0003' 
				('\u0001' {LEXSTATE->type=SHA224DSAOID;pss_constructed_bit_flag=1-pss_constructed_bit_flag;dsa_counter++;constructed_bit+=dsa_counter;}
				|'\u0002' {LEXSTATE->type=SHA256DSAOID;pss_constructed_bit_flag=1-pss_constructed_bit_flag;dsa_counter++;constructed_bit+=dsa_counter;}
				|('\u0000' | '\u0003'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;}
				){counter_primitive-=9;oid=0;goto ruleHASHOIDEx;}
			|('\u0000'..'\u0001' | '\u0004'..'\u00FF'){oid=0;LEXSTATE->type = VALUE;counter_primitive-=8;goto ruleHASHOIDEx;}
			)
		|('\u0000'..'\u0003' | '\u0005'..'\u00FF'){oid=0;LEXSTATE->type = VALUE;counter_primitive-=7;goto ruleHASHOIDEx;}
		)
	|'\u0002'
		('\u0001' 
			('\u0001' 
				('\u0016' {LEXSTATE->type=KEAPKOID;pss_constructed_bit_flag=1-pss_constructed_bit_flag;}
				|('\u0000'..'\u0015' | '\u0017'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;}
				){counter_primitive-=9;oid=0;goto ruleHASHOIDEx;}
			|('\u0000' | '\u0002'..'\u00FF'){oid=0;LEXSTATE->type = VALUE;counter_primitive-=8;goto ruleHASHOIDEx;}
			)
		|('\u0000' | '\u0002'..'\u00FF'){oid=0;LEXSTATE->type = VALUE;counter_primitive-=7;goto ruleHASHOIDEx;}
		)
	|('\u0000'..'\u0001' | '\u0004'..'\u00FF'){oid=0;LEXSTATE->type = VALUE;counter_primitive-=6;goto ruleHASHOIDEx;}	
	)
	|('\u0000'..'\u0064' | '\u0066'..'\u00FF'){oid=0;LEXSTATE->type = VALUE;counter_primitive-=5;goto ruleHASHOIDEx;})|('\u0000'| '\u0002'..'\u00FF'){oid=0;LEXSTATE->type = VALUE;counter_primitive-=4;goto ruleHASHOIDEx;})|('\u0000'..'\u0047' | '\u0049'..'\u00FF'){oid=0;LEXSTATE->type = VALUE;counter_primitive-=3;goto ruleHASHOIDEx;}) |('\u0000'..'\u0085' | '\u0087'..'\u00FF'){oid=0;LEXSTATE->type = VALUE;counter_primitive-=2;goto ruleHASHOIDEx;})|('\u0000'..'\u0059' | '\u0061'..'\u00FF'){oid=0;LEXSTATE->type = VALUE;counter_primitive--;goto ruleHASHOIDEx;}
	);
	
DSADHOID	:	{counter_primitive == 7 && oid}?=>('\u002A' ('\u0086' ('\u0048' ('\u00CE' 
	('\u0038'
		('\u0004' 
			('\u0003' {LEXSTATE->type=SHA1DSAOID;pss_constructed_bit_flag=1-pss_constructed_bit_flag;dsa_counter++;constructed_bit+=dsa_counter;}
			|'\u0001' {LEXSTATE->type=DSAPKOID;constructed_bit=1;pss_constructed_bit_flag=1-pss_constructed_bit_flag;}
			|('\u0000'|'\u0002' | '\u0004'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;}
			){counter_primitive-=7;oid=0;goto ruleDSADHOIDEx;}
		| ('\u0000'..'\u0003' | '\u0005'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=6;goto ruleDSADHOIDEx;}
		)
	|'\u003E' 
		('\u0002' 
			('\u0001' {LEXSTATE->type=DHPKOID;constructed_bit=1;pss_constructed_bit_flag=1-pss_constructed_bit_flag;}
			|('\u0000'| '\u0002'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;}
			){counter_primitive-=7;oid=0;goto ruleDSADHOIDEx;}
		| ('\u0000'..'\u0001' | '\u0003'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=6;goto ruleDSADHOIDEx;}
		)
	| ('\u0000'..'\u0037' | '\u0039'..'\u003D' |'\u003F'..'\u00FF' ) {oid=0;LEXSTATE->type = VALUE;counter_primitive-=5;goto ruleDSADHOIDEx;}
	)
	| ('\u0000'..'\u00CD' | '\u00CF'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=4;goto ruleDSADHOIDEx;})|  ('\u0000'..'\u0047' | '\u0049'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=3;goto ruleDSADHOIDEx;})|  ('\u0000'..'\u0085' | '\u0087'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=2;goto ruleDSADHOIDEx;})| ('\u0000'..'\u0029' | '\u002B'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive--;goto ruleDSADHOIDEx;});

GOSTOID	:	{counter_primitive == 6 && oid}?=> ('\u002A' ('\u0085' ('\u0003' ('\u0002' ('\u0002' 
	('\u0014' {LEXSTATE->type=GOST94PK;pss_constructed_bit_flag=1-pss_constructed_bit_flag;constructed_bit=1;}
	|'\u0013' {LEXSTATE->type=GOST01PK;pss_constructed_bit_flag=1-pss_constructed_bit_flag;constructed_bit=1;}
	|'\u0004' {LEXSTATE->type=GOST94SIGN;pss_constructed_bit_flag=1-pss_constructed_bit_flag;}
	|'\u0003' {LEXSTATE->type=GOST01SIGN;pss_constructed_bit_flag=1-pss_constructed_bit_flag;}
	| ('\u0000'..'\u0002' | '\u0005'..'\u0012'  | '\u0015'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;}
	){counter_primitive-=6;oid=0;goto ruleGOSTOIDEx;}
	|  ('\u0000'..'\u0001' | '\u0003'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=5;goto ruleGOSTOIDEx;})|  ('\u0000'..'\u0001' | '\u0003'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=4;goto ruleGOSTOIDEx;})|  ('\u0000'..'\u0002' | '\u0004'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=3;goto ruleGOSTOIDEx;})|  ('\u0000'..'\u0084' | '\u0086'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=2;goto ruleGOSTOIDEx;})|  ('\u0000'..'\u0029' | '\u002B'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive--;goto ruleGOSTOIDEx;});

SHA1OID	:	{counter_primitive==5 && oid}?=> ('\u002B' ('\u000E' ('\u0003' ('\u0002' 
	('\u001A' {LEXSTATE->type=SHA1OID;}
	| ('\u0000'..'\u0019' | '\u001B'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;}
	){counter_primitive-=5;oid=0;goto ruleSHA1OIDEx;}
	|  ('\u0000'..'\u0001' | '\u0003'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=4;goto ruleSHA1OIDEx;})|  ('\u0000'..'\u0002' | '\u0004'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=3;goto ruleSHA1OIDEx;})|  ('\u0000'..'\u000D' | '\u000F'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive-=2;goto ruleSHA1OIDEx;})|  ('\u0000'..'\u002A' | '\u002C'..'\u00FF') {oid=0;LEXSTATE->type = VALUE;counter_primitive--;goto ruleSHA1OIDEx;});

ECKAOID	:	{counter_primitive==5 && oid}?=>('\u002B'('\u0081'('\u0004'('\u0001'
	('\u000C' {LEXSTATE->type=ECDHOID;}
	|'\u000D' {LEXSTATE->type=ECMQVOID;}
	|('\u0000'..'\u000B'|'\u000E'..'\u00FF') {LEXSTATE->type = VALUE;}
	){counter_primitive-=5;oid=0;goto ruleECKAOIDEx;}
	|('\u0000'|'\u0002'..'\u00FF'){oid=0;LEXSTATE->type = VALUE;counter_primitive-=4;goto ruleECKAOIDEx;})
	|('\u0000'..'\u0003'|'\u0005'..'\u00FF'){oid=0;LEXSTATE->type = VALUE;counter_primitive-=3;goto ruleECKAOIDEx;})
	|('\u0000'..'\u0080'|'\u0082'..'\u00FF'){oid=0;LEXSTATE->type = VALUE;counter_primitive-=2;goto ruleECKAOIDEx;})
	|('\u0000'..'\u002A'|'\u002C'..'\u00FF'){oid=0;LEXSTATE->type = VALUE;counter_primitive-=1;goto ruleECKAOIDEx;})
	;

//DNOID
OIDCN 	:	{counter_primitive<0}?=>'\u0000';
OIDON 	:	{counter_primitive<0}?=>'\u0000';
NAMEOID 	:	{counter_primitive<0}?=>'\u0000';
SURNAMEOID:	{counter_primitive<0}?=>'\u0000';
OIDGIVENAME 	:{counter_primitive<0}?=>'\u0000';
OIDINIT 	:	{counter_primitive<0}?=>'\u0000';
OIDGENQUALIFIER 	:{counter_primitive<0}?=>'\u0000';
OIDLOCAL 	:	{counter_primitive<0}?=>'\u0000';
OIDSORP 	:	{counter_primitive<0}?=>'\u0000';
OIDOU 	:	{counter_primitive<0}?=>'\u0000';
OIDTITLE 	:	{counter_primitive<0}?=>'\u0000';
OIDDNQUALIFIER 	:{counter_primitive<0}?=>'\u0000';
OIDCOUNTRY 	:{counter_primitive<0}?=>'\u0000';
OIDSERIAL 	:	{counter_primitive<0}?=>'\u0000';
OIDPSEUDO 	:	{counter_primitive<0}?=>'\u0000';

//EXTSOID
OIDAKI	:	{counter_primitive<0}?=>'\u0000';
OIDSKI	:	{counter_primitive<0}?=>'\u0000';
OIDCERTPOL	:	{counter_primitive<0}?=>'\u0000';
ANYPOLICYOID	:{counter_primitive<0}?=>'\u0000';
OIDKEYUS	:	{counter_primitive<0}?=>'\u0000';
OIDPOLMAP	:	{counter_primitive<0}?=>'\u0000';
OIDSUBALT	:	{counter_primitive<0}?=>'\u0000';
OIDISSALT	:	{counter_primitive<0}?=>'\u0000';
OIDSUBDIR	:	{counter_primitive<0}?=>'\u0000';
OIDBC	:	{counter_primitive<0}?=>'\u0000';
OIDNAME	:	{counter_primitive<0}?=>'\u0000';
OIDPOLCONST	:{counter_primitive<0}?=>'\u0000';
OIDEXTKEY	:	{counter_primitive<0}?=>'\u0000';
ANYUSAGEOID	:{counter_primitive<0}?=>'\u0000';
OIDCRL	:	{counter_primitive<0}?=>'\u0000';
OIDINHIBIT	:	{counter_primitive<0}?=>'\u0000';
OIDFRESHCRL	:{counter_primitive<0}?=>'\u0000';

//PRIVATEEXTSOID
AIAOID	:	{counter_primitive<0}?=>'\u0000';
SIAOID 	:	{counter_primitive<0}?=>'\u0000';
CAISSUEROID 
	:	{counter_primitive<0}?=>'\u0000';
OCSPOID  	:	{counter_primitive<0}?=>'\u0000';
CAREPOOID  	:	{counter_primitive<0}?=>'\u0000';
TSPOID  	:	{counter_primitive<0}?=>'\u0000';
CPSOID  	:	{counter_primitive<0}?=>'\u0000';
UNOTICEOID :	{counter_primitive<0}?=>'\u0000';
SERVERAUTHOID :	{counter_primitive<0}?=>'\u0000';
CLIENTAUTHOID :	{counter_primitive<0}?=>'\u0000';
CODESIGNOID :	{counter_primitive<0}?=>'\u0000';
EMAILPROTECTOID :	{counter_primitive<0}?=>'\u0000';
TIMESTAMPOID :	{counter_primitive<0}?=>'\u0000';
OCSPSIGNOID :	{counter_primitive<0}?=>'\u0000';

//RSAOID
RSAPKOID	:	{counter_primitive<0}?=>'\u0000';
MGF1OID	:	{counter_primitive<0}?=>'\u0000';
RSAPSSOID	:	{counter_primitive<0}?=>'\u0000';
RSAOAEPOID	:	{counter_primitive<0}?=>'\u0000';
PSPECOID	:	{counter_primitive<0}?=>'\u0000';
MD2RSAOID	:	{counter_primitive<0}?=>'\u0000';
MD5RSAOID	:	{counter_primitive<0}?=>'\u0000';
SHA1RSAOID	:	{counter_primitive<0}?=>'\u0000';
SHA224RSAOID	:{counter_primitive<0}?=>'\u0000';
SHA256RSAOID	:{counter_primitive<0}?=>'\u0000';
SHA384RSAOID	:{counter_primitive<0}?=>'\u0000';
SHA512RSAOID	:{counter_primitive<0}?=>'\u0000';
LEGACYEMAILOID	:{counter_primitive<0}?=>'\u0000';

//ECOID
ECPKOID	:	{counter_primitive<0}?=>'\u0000';
PRIMEOID	:	{counter_primitive<0}?=>'\u0000';
BASIS2OID	:	{counter_primitive<0}?=>'\u0000';
GNBASISOID	:	{counter_primitive<0}?=>'\u0000';
TPBASISOID	:	{counter_primitive<0}?=>'\u0000';
PPBASISOID	:	{counter_primitive<0}?=>'\u0000';
SHA1ECOID	:	{counter_primitive<0}?=>'\u0000';
SHA224ECOID	:{counter_primitive<0}?=>'\u0000';
SHA256ECOID	:{counter_primitive<0}?=>'\u0000';
SHA384ECOID	:{counter_primitive<0}?=>'\u0000';
SHA512ECOID	:{counter_primitive<0}?=>'\u0000';

//HASHOID
SHA224OID	:	{counter_primitive<0}?=>'\u0000';
SHA256OID	:	{counter_primitive<0}?=>'\u0000';
SHA384OID	:	{counter_primitive<0}?=>'\u0000';
SHA512OID	:	{counter_primitive<0}?=>'\u0000';
KEAPKOID	:	{counter_primitive<0}?=>'\u0000';
SHA224DSAOID	:{counter_primitive<0}?=>'\u0000';
SHA256DSAOID	:{counter_primitive<0}?=>'\u0000';

//DSADHOID
DSAPKOID	:	{counter_primitive<0}?=>'\u0000';
DHPKOID	:	{counter_primitive<0}?=>'\u0000';
SHA1DSAOID	:	{counter_primitive<0}?=>'\u0000';

//GOSTOID
GOST94PK 		:{counter_primitive<0}?=>'\u0000';
GOST01PK 	:	{counter_primitive<0}?=>'\u0000';
GOST94SIGN 	:	{counter_primitive<0}?=>'\u0000';
GOST01SIGN 	:	{counter_primitive<0}?=>'\u0000';

//ECKAOID
ECDHOID	:	{counter_primitive<0}?=>'\u0000';
ECMQVOID	:	{counter_primitive<0}?=>'\u0000';

//ZEROS 	:	({counter_primitive>0 && bool}?=> '\u0000' {printf("counter is \%d \n",counter_primitive);counter_primitive--;})+{bool=0;if(counter_primitive>0){printf("length too short \n");exit(1);}};

PRINTABLE	:	  {counter_primitive>0}?=> '\u0001'..'\u00FF' {printf("counter printable is \%d \n",counter_primitive);oid=0;counter_primitive--; 
	};


	
fragment VAL4   :         '\u0000'..'\u007F' VAL VAL VAL;    
fragment VAL2   :         VAL VAL;
fragment VAL	:	  '\u0000'..'\u00FF' ;

VALUE	:	  {counter_primitive>0}?=> '\u0000'..'\u00FF' {printf("counter is \%d \n",counter_primitive);oid=0;counter_primitive--;
			} 
	;

EVERY 	:	 {counter_primitive==0}?=> err='\u0000'..'\u00FF'{printf("lexing error matching tag \%d \n",$err);printf("counter_primitive is \%d \n",counter_primitive);
if($err == 36 || $err == 35)
exit(100);
else
exit(1);};

//EOFTOKEN 	:  		{counter_primitive==0}?=>EOF;
