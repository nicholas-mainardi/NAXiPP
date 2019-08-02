//error codes
#define OK_CODE 0
#define LEXING_ERROR 1
#define SEQUENCE_LENGTH_ERROR 2
#define KEA_DOMAINID_LENGTH_ERROR 3
#define SIGNATURE_PARAMS_MATCHING_ERROR 4
#define DSA_SIGNATURE_PARAMS_MATCHING_ERROR 5
#define GOST_SIGNATURE_PARAMS_MATCHING_ERROR 6
#define DH_KEY_NOT_INTEGER_ERROR 7
#define DEFINED_ATTRS_STACK_SIZE_ERROR 10
#define EXTENSIONS_ATTRS_STACK_SIZE_ERROR 11
#define OU_STACK_SIZE_ERROR 12
#define X509_DNAME_ERROR 14
#define PRINT_STRING_REGEXP_ERROR 15
#define IA5_STRING_REGEXP_ERROR 16
#define UTC_REGEXP_ERROR 17
#define GENERALIZED_TIME_REGEXP_ERROR 18
#define T61_STRING_REGEXP_ERROR 19
#define BMP_STRING_REGEXP_ERROR 20
#define VISIBLE_STRING_REGEXP_ERROR 21
#define NUMERIC_STRING_REGEXP_ERROR 22
#define DUPLICATED_EXTENSION 23
#define DUPLICATED_POLICY 24
#define KEY_USAGE_CONSTRAINT_ERROR 25
#define KEY_AGREEMENT_DECYPHER_ONLY_ERROR 26
#define KEY_AGREEMENT_ENCYPHER_ONLY_ERROR 27
#define KEY_USAGE_NO_BITS_SET 28
#define BC_NOT_CRITICAL_ERROR 29
#define MISSING_CRITICAL_BC_SKI_ERROR 30
#define MISSING_SKI_ERROR 31
#define EMPTY_ACCESS_DESCRIPTION_LIST_ERROR 32
#define EMPTY_GENERAL_NAMES_ERROR 33
#define EMPTY_PRINTABLE_STRING_ERROR 34
#define WRONG_VERSION_ERROR 35
#define PATHLEN_NO_CA_ERROR 36
#define MISSING_CA_ERROR 37
#define MISSING_EXTENSION_TAG3_ERROR 38
#define UNEXPECTED_CERT_SIGN_BIT_ERROR 39
#define WRONG_STRING_TYPE_ERROR 40
#define EXTENSION_NO_VERSION3_ERROR 41
#define DN_WRONG_OID 42
#define PATHLEN_NO_BC_CRITICAL_ERROR 43
#define EMPTY_VALUE_ERROR 44
#define MISSING_SKI_AND_CERT_SIGN_ERROR 45
#define CRITICAL_EXTENSION_ERROR 46
#define EMPTY_NUMERIC_TAG_ERROR 47
#define POLICY_WRONG_OID_ERROR 48
#define MISSING_CERT_SIGN_ERROR 49
#define CERT_SIGN_ASN1_ENCODING_ERROR 50
#define GENERAL_SUBTREES_EMPTY_ERROR 51
#define EMPTY_RDNS_ERROR 52
#define WRONG_ALG_ID_OID_ERROR 53
#define REPEATED_BC_ERROR 55
#define EMPTY_EXTENSIONS_LIST_ERROR 56
#define EXTENSION_WRONG_OID_ERROR 57
#define UNEXPECTED_NULL_ALG_ID_PARAMS_ERROR 58
#define MISSING_AKI_KEY_ID_ERROR 60
#define LENGTH_FIELD_BOUND_EXCEEDED 61
#define BAD_OID_TERMINATOR_ERROR 62
#define OID_ARC_OVERFLOW_ERROR 63
#define TRUNCATED_FILE_ERROR 64
#define NEGATIVE_PATHLEN_ERROR 65
#define BAD_BITSTRING_ENCODING_ERROR 66
#define END_OF_CERT_EXPECTED_ERROR 67
#define GENERIC_ERROR 255

#define DISPLAY_STRING_LENGTH_WARNING 1
#define ATTRIBUTE_STRING_LENGTH_WARNING 2
#define INTEGER_BOUNDS_WARNING 4
#define NO_CONSISTENT_USAGE_FOUND_WARNING 8
#define SERIAL_NUMBER_TOO_LONG_WARNING 16
#define NEGATIVE_SERIAL_NUMBER_WARNING 32
#define CA_REPO_NO_CA_WARNING 64
#define TSP_CA_WARNING 128
#define IA5STRING_MISUSE_WARNING 256
#define UNCONSISTENT_USAGE_FOUND_WARNING 512
#define BAD_URI_FORMAT_WARNING 1024
#define BAD_DNS_FORMAT_WARNING 2048
#define BAD_EMAIL_FORMAT_WARNING 4096


#define ub_pseudonym 128
#define ub_country_name_numeric_length 3
#define ub_domain_name_length 16
#define ub_x121_address_length 16
#define ub_terminal_id_length 24
#define ub_organization_name_length 64
#define ub_numeric_user_id_length 32
#define ub_surname_length 40
#define ub_given_name_length 16
#define ub_initials_length 5
#define ub_generation_qualifier_length 3
#define ub_organizational_unit_name_length 32
#define ub_organizational_units 4 
#define ub_domain_defined_attributes 4
#define ub_domain_defined_attribute_type_length 8
#define ub_domain_defined_attribute_value_length 128
#define ub_common_name_length 64
#define ub_pds_name_length 16
#define ub_country_name_numeric_length 3
#define ub_country_name_alpha_length 2
#define ub_postal_code_length 16
#define ub_pds_parameter_length 30
#define ub_pds_physical_address_lines 6
#define ub_unformatted_address_length 180
#define ub_e163_4_number_length 15
#define ub_e163_4_sub_address_length 40
#define ub_extensions_attributes 256

#ifdef DIRSTRING_TYPE
#undef DIRSTRING_TYPE
#endif
#define DIRSTRING_TYPE (B_ASN1_PRINTABLESTRING|B_ASN1_T61STRING|B_ASN1_BMPSTRING|B_ASN1_UTF8STRING|B_ASN1_IA5STRING|B_ASN1_UNIVERSALSTRING)

#define DEBUG
#define DEPLOY

#ifdef DEPLOY
#define printf(...)
#define gmp_printf(...)
#endif

void compute_names();

//#define exit(code) do{compute_names();exit(code);}while(0)
#define exit(code) do{fprintf(stdout,"%d",warning);exit(code);}while(0)
//#define exit(code) do{end=clock();double time = (double) (end-begin)/CLOCKS_PER_SEC;fprintf(stdout,"%f",time);exit(code);}while(0)
typedef struct count counter;
typedef struct list oid_list;
typedef struct objid oid_array;
typedef struct rule_name rule;
typedef struct rule_tree RULE_TREE;
//typedef struct bs bit_string;
typedef struct tags tag_type;
typedef struct any ANY;
//algorithm id paramters
typedef struct dsa_parameters dsa_params;
typedef struct pss_paramters pss_params;
typedef struct gost_parameters gost_params;
typedef struct dh_parameters dh_params;
typedef struct kea_parameters kea_params;
typedef struct oaep_parameters oaep_params;
typedef union ecpk_parameters ecpk_params;
typedef struct ec_parameters ec_params;
typedef struct penta_parameters penta_params;
typedef union char_two_parameters char_two_params;
typedef struct characteristic2 characteristic_two;
typedef union field_parameters field_params;
typedef struct field_id FIELD_ID;
typedef union alg_params alg_id_params;
typedef struct alg_id ALG_ID;
//signatures
typedef struct dsa_signature DSA_signature;
typedef union signature X509_SIGNATURE;
//public keys
typedef struct rsa_pk RSA_KEY;
typedef struct pubkey_alg PUBKEY_ALG;
typedef union pubkey PUBKEY;
//extensions
typedef struct x509_exts x509_EXTENSION;
typedef union x509_exts_value X509_EXTENSION_VALUE;
typedef struct auth_key_id AUTH_KEY_ID;
typedef struct policy_info POLICY_INFO;
typedef struct policy_qualifier POLICY_QUALIFIER;
typedef union qualifier QUALIFIER;
typedef struct general_name GEN_NAME;
typedef union field_general_name field_gen_name;
typedef struct other_name_st other_name;
typedef struct subject_dir_attrs SUBJECT_DIRECTORY_ATTRIBUTES;
typedef union sub_dir_attrs_value SUB_DIR_ATTRS_VALUE;
typedef struct bc BASIC_CONSTRAINT;
typedef struct name_constraints NAME_CONSTRAINT;
typedef struct general_subtree GENERAL_SUBTREES;
typedef struct dps CRL_DISTRIBUTION_POINT;
typedef union dp DP_NAME;
typedef struct access_description ACCESS_DESCRIPTIONS;
//x400 types
typedef struct x400 x400_address;
typedef struct standard_attributes standard_attrs;
typedef struct defined_attributes defined_attrs;
typedef struct extensions_attributes extensions_attrs;
typedef union exts_attrs_value EXTS_ATTRS_VALUE;
typedef struct pds_param PDS_PARAMETER;
typedef struct psap_addr PSAP_ADDR;
typedef struct e163_4 E163_4_ADDR;
typedef struct person_name PERSONAL_NAME;
typedef struct upa UNFORMATTED_POSTAL_ADDRESS;
typedef struct ci cert_info;
//X509_DNAME
typedef struct x509_string_name X509_STRING_NAME;
typedef union x509_dname_entry X509_DNAME_ENTRY;

typedef ASN1_STRING* STRING_POINTER;
#ifndef DECLARE_STACK_OF
DEFINE_STACK_OF(STRING_POINTER)
#else
DECLARE_STACK_OF(STRING_POINTER)
#define sk_STRING_POINTER_new_null() SKM_sk_new_null(STRING_POINTER)
#define sk_STRING_POINTER_push(st,val) SKM_sk_push(STRING_POINTER,st,val)
#define sk_STRING_POINTER_num(st) SKM_sk_num(STRING_POINTER,st)
#endif

typedef defined_attrs* DEFINED_ATTRS_POINTER;
#ifndef DECLARE_STACK_OF
DEFINE_STACK_OF(DEFINED_ATTRS_POINTER)
#else
DECLARE_STACK_OF(DEFINED_ATTRS_POINTER)
#define sk_DEFINED_ATTRS_POINTER_new_null() SKM_sk_new_null(DEFINED_ATTRS_POINTER)
#define sk_DEFINED_ATTRS_POINTER_push(st,val) SKM_sk_push(DEFINED_ATTRS_POINTER,st,val)
#define sk_DEFINED_ATTRS_POINTER_num(st) SKM_sk_num(DEFINED_ATTRS_POINTER,st)
#endif

typedef extensions_attrs* EXTENSIONS_ATTRS_POINTER;
#ifndef DECLARE_STACK_OF
DEFINE_STACK_OF(EXTENSIONS_ATTRS_POINTER)
#else
DECLARE_STACK_OF(EXTENSIONS_ATTRS_POINTER)
#define sk_EXTENSIONS_ATTRS_POINTER_new_null() SKM_sk_new_null(EXTENSIONS_ATTRS_POINTER)
#define sk_EXTENSIONS_ATTRS_POINTER_push(st,val) SKM_sk_push(EXTENSIONS_ATTRS_POINTER,st,val)
#define sk_EXTENSIONS_ATTRS_POINTER_num(st) SKM_sk_num(EXTENSIONS_ATTRS_POINTER,st)
#endif

typedef GEN_NAME* GENERAL_NAME_POINTER;
#ifndef DECLARE_STACK_OF
DEFINE_STACK_OF(GENERAL_NAME_POINTER)
#else
DECLARE_STACK_OF(GENERAL_NAME_POINTER)
#define sk_GENERAL_NAME_POINTER_new_null() SKM_sk_new_null(GENERAL_NAME_POINTER)
#define sk_GENERAL_NAME_POINTER_push(st,val) SKM_sk_push(GENERAL_NAME_POINTER,st,val)
#define sk_GENERAL_NAME_POINTER_num(st) SKM_sk_num(GENERAL_NAME_POINTER,st)
#define sk_GENERAL_NAME_POINTER_value(st,i) SKM_sk_value(GENERAL_NAME_POINTER,st,i)
#endif

#ifndef DECLARE_STACK_OF
DEFINE_STACK_OF(POLICY_INFO)
#else
DECLARE_STACK_OF(POLICY_INFO)
#define sk_POLICY_INFO_new_null() SKM_sk_new_null(POLICY_INFO)
#define sk_POLICY_INFO_push(st,val) SKM_sk_push(POLICY_INFO,st,val)
#define sk_POLICY_INFO_num(st) SKM_sk_num(POLICY_INFO,st)
#endif

#ifndef DECLARE_STACK_OF
DEFINE_STACK_OF(POLICY_QUALIFIER)
#else
DECLARE_STACK_OF(POLICY_QUALIFIER)
#define sk_POLICY_QUALIFIER_new_null() SKM_sk_new_null(POLICY_QUALIFIER)
#define sk_POLICY_QUALIFIER_push(st,val) SKM_sk_push(POLICY_QUALIFIER,st,val)
#define sk_POLICY_QUALIFIER_num(st) SKM_sk_num(POLICY_QUALIFIER,st)
#endif

#ifndef DECLARE_STACK_OF
DEFINE_STACK_OF(SUBJECT_DIRECTORY_ATTRIBUTES)
#else
DECLARE_STACK_OF(SUBJECT_DIRECTORY_ATTRIBUTES)
#define sk_SUBJECT_DIRECTORY_ATTRIBUTES_new_null() SKM_sk_new_null(SUBJECT_DIRECTORY_ATTRIBUTES)
#define sk_SUBJECT_DIRECTORY_ATTRIBUTES_push(st,val) SKM_sk_push(SUBJECT_DIRECTORY_ATTRIBUTES,st,val)
#define sk_SUBJECT_DIRECTORY_ATTRIBUTES_num(st) SKM_sk_num(SUBJECT_DIRECTORY_ATTRIBUTES,st)
#endif

#ifndef DECLARE_STACK_OF
DEFINE_STACK_OF(GENERAL_SUBTREES)
#else
DECLARE_STACK_OF(GENERAL_SUBTREES)
#define sk_GENERAL_SUBTREES_new_null() SKM_sk_new_null(GENERAL_SUBTREES)
#define sk_GENERAL_SUBTREES_push(st,val) SKM_sk_push(GENERAL_SUBTREES,st,val)
#define sk_GENERAL_SUBTREES_num(st) SKM_sk_num(GENERAL_SUBTREES,st)
#endif

#ifndef DECLARE_STACK_OF
DEFINE_STACK_OF(CRL_DISTRIBUTION_POINT)
#else
DECLARE_STACK_OF(CRL_DISTRIBUTION_POINT)
#define sk_CRL_DISTRIBUTION_POINT_new_null() SKM_sk_new_null(CRL_DISTRIBUTION_POINT)
#define sk_CRL_DISTRIBUTION_POINT_push(st,val) SKM_sk_push(CRL_DISTRIBUTION_POINT,st,val)
#define sk_CRL_DISTRIBUTION_POINT_num(st) SKM_sk_num(CRL_DISTRIBUTION_POINT,st)
#endif

#ifndef DECLARE_STACK_OF
DEFINE_STACK_OF(ACCESS_DESCRIPTIONS)
#else
DECLARE_STACK_OF(ACCESS_DESCRIPTIONS)
#define sk_ACCESS_DESCRIPTIONS_new_null() SKM_sk_new_null(ACCESS_DESCRIPTIONS)
#define sk_ACCESS_DESCRIPTIONS_push(st,val) SKM_sk_push(ACCESS_DESCRIPTIONS,st,val)
#define sk_ACCESS_DESCRIPTIONS_num(st) SKM_sk_num(ACCESS_DESCRIPTIONS,st)
#endif

#ifndef DECLARE_STACK_OF
DEFINE_STACK_OF(x509_EXTENSION)
#else
DECLARE_STACK_OF(x509_EXTENSION)
#define sk_x509_EXTENSION_new_null() SKM_sk_new_null(x509_EXTENSION)
#define sk_x509_EXTENSION_push(st,val) SKM_sk_push(x509_EXTENSION,st,val)
#define sk_x509_EXTENSION_num(st) SKM_sk_num(x509_EXTENSION,st)
#define sk_x509_EXTENSION_value(st,i) SKM_sk_value(x509_EXTENSION,st,i)
#endif

#ifndef DECLARE_STACK_OF
DEFINE_STACK_OF(X509_DNAME_ENTRY)
#else
DECLARE_STACK_OF(X509_DNAME_ENTRY)
#define sk_X509_DNAME_ENTRY_new_null() SKM_sk_new_null(X509_DNAME_ENTRY)
#define sk_X509_DNAME_ENTRY_push(st,val) SKM_sk_push(X509_DNAME_ENTRY,st,val)
#define sk_X509_DNAME_ENTRY_num(st) SKM_sk_num(X509_DNAME_ENTRY,st)
#define sk_X509_DNAME_ENTRY_value(st,i) SKM_sk_value(X509_DNAME_ENTRY,st,i)
#endif

struct rule_name{
    char *fname;
    rule *next;
};

struct rule_tree{
    rule *rule_list;
    int depth;
    RULE_TREE *next;
};

struct count{
mpz_t counter;
mpz_t start_counter;
counter *next;
};

struct list{
mpz_t index;
oid_list *next;
};

struct objid{
mpz_t *oid;
int len;
ASN1_OBJECT *obj;
};

/*struct bs{
unsigned char *value;
unsigned long length;
unsigned char offset;
};*/

struct tags{
int length;
unsigned char *value;
};

struct any{
    void *el;
    ANY* next;
};

struct dsa_parameters{
    ASN1_INTEGER *p;
    ASN1_INTEGER *q;
    ASN1_INTEGER *g;
};

struct pss_paramters{
    ASN1_OBJECT *hash_func;
    ASN1_OBJECT *mgf1_hash_func;
    ASN1_INTEGER *salt_length;
    ASN1_INTEGER *trailer_field;
};

struct oaep_parameters{
    ASN1_OBJECT *hash_func;
    ASN1_OBJECT *mgf1_hash_func;
    ASN1_OCTET_STRING *P;
};

struct gost_parameters{
    ASN1_OBJECT *public_key_param_set;
    ASN1_OBJECT *digest_param_set;
    ASN1_OBJECT *encryption_param_set;
};

struct dh_parameters{
    ASN1_INTEGER *p;
    ASN1_INTEGER *g;
    ASN1_INTEGER *q;
    ASN1_INTEGER *j;
    ASN1_STRING *seed;
    ASN1_INTEGER *pgen_counter;
};

struct kea_parameters{
    ASN1_OCTET_STRING *domain_id;
};

struct penta_parameters{
    ASN1_INTEGER *k1;
    ASN1_INTEGER *k2;
    ASN1_INTEGER *k3;
};

union char_two_parameters{
    ASN1_INTEGER *trinomial;
    penta_params *pentanomial;
    ANY *any;
};

struct characteristic2{
    ASN1_INTEGER *m;
    ASN1_OBJECT *basis;
    char_two_params *char_two_params;
};

union field_parameters{
    ASN1_INTEGER *p;
    characteristic_two *char_two;
    ANY *any;
};

struct field_id{
    ASN1_OBJECT *field_type;
    field_params *field_params;
};

struct ec_parameters{
    FIELD_ID *field;
    ASN1_OCTET_STRING *a;
    ASN1_OCTET_STRING *b;
    ASN1_STRING *seed;
    ASN1_OCTET_STRING *base;
    ASN1_INTEGER *order;
    ASN1_INTEGER *cofactor;
};

union ecpk_parameters{
    ASN1_OBJECT *named_curve;
    ec_params *ec;
};

union alg_params{
        dsa_params dsa;
        pss_params pss;
        gost_params gost;
        dh_params dh;
        kea_params kea;
        oaep_params oaep;
        ecpk_params *ecpk;
    };

struct alg_id{
    ASN1_OBJECT *oid;
    alg_id_params *params;
};

struct dsa_signature{
    ASN1_INTEGER *r;
    ASN1_INTEGER *s;
};

struct rsa_pk{
    ASN1_INTEGER *n;
    ASN1_INTEGER *e;
};

union pubkey{
    ASN1_STRING *bitstring_encoding;
    ASN1_INTEGER *dsa_dh_key;
    ASN1_STRING *gost_key;
    RSA_KEY *rsa; 
};

union signature
{
    ASN1_STRING *sign;
    DSA_signature *dsa_sign;
};

struct pubkey_alg{
    ALG_ID *alg;
    PUBKEY *pubkey;
};

struct standard_attributes{
    ASN1_STRING *country_name;
    ASN1_STRING *ad_name;
    ASN1_STRING *net_addr;
    ASN1_STRING *terminal_id;
    ASN1_STRING *private_domain_name;
    ASN1_STRING *organization_name;
    ASN1_STRING *numeric_user_identifier;
    ASN1_STRING *surname;
    ASN1_STRING *given_name;
    ASN1_STRING *initials;
    ASN1_STRING *generation_qualifier;
    STACK_OF(STRING_POINTER) *organizational_unit_names;
};

struct defined_attributes{
    ASN1_STRING *type;
    ASN1_STRING *value;
};

struct person_name{
    ASN1_T61STRING *surname;
    ASN1_T61STRING *given_name;
    ASN1_T61STRING *initials;
    ASN1_T61STRING *gen_qualifier;
};

struct pds_param{
    ASN1_PRINTABLESTRING *printable;
    ASN1_T61STRING *teletex;
};

struct upa{
    STACK_OF(STRING_POINTER) *printable_addr;
    ASN1_T61STRING *t_string;
};

struct e163_4{
    ASN1_STRING *number;
    ASN1_STRING *sub_address;
};

struct psap_addr{
    ASN1_OCTET_STRING *p_selector;
    ASN1_OCTET_STRING *s_selector;
    ASN1_OCTET_STRING *t_selector;
    STACK_OF(STRING_POINTER)* n_addresses;
};

union exts_attrs_value{
    ASN1_STRING *str_value;
    PERSONAL_NAME *personal_name;
    STACK_OF(STRING_POINTER) *organizational_unit_names;
    PDS_PARAMETER *pds_parameter;
    UNFORMATTED_POSTAL_ADDRESS *upa;
    E163_4_ADDR *e163_4;
    PSAP_ADDR *psap;
    STACK_OF(DEFINED_ATTRS_POINTER) *domain_defined;
    ANY *any;
};

struct extensions_attributes{
    int type;
    EXTS_ATTRS_VALUE *value;
};

struct other_name_st{
    ASN1_OBJECT *oid;
    ANY *value;
};

union field_general_name{
    other_name *other_name;
    ASN1_IA5STRING *rfc822name;
    ASN1_IA5STRING *DNSname;
    x400_address *x400_addr;
    STACK_OF(X509_DNAME_ENTRY) *dn;  
    EDIPARTYNAME *edi;
    ASN1_IA5STRING *uri;
    ASN1_OCTET_STRING *IP_addr;
    ASN1_OBJECT *registered_id;
};

struct general_name{
    int tag;
    field_gen_name *name;
};

struct x400{
    standard_attrs *standard_attributes;
    STACK_OF(DEFINED_ATTRS_POINTER) *defined_attributes;
    STACK_OF(EXTENSIONS_ATTRS_POINTER) *extensions_attributes;
};

struct subject_alternative_name_exts{
    int critical;
    STACK_OF(GENERAL_NAME_POINTER) *gen_names;
};

struct auth_key_id{
    ASN1_OCTET_STRING *key_id;
    STACK_OF(GENERAL_NAME_POINTER) *auth_cert_issuer;
    ASN1_INTEGER *cert_serial_number;
};

union qualifier{
    ASN1_IA5STRING *cps;
    USERNOTICE *unotice;
    ANY *any;
};

struct policy_qualifier{
    ASN1_OBJECT *oid;
    QUALIFIER *qualifier;
};

struct policy_info{
    ASN1_OBJECT *oid;
    STACK_OF(POLICY_QUALIFIER) *qualifiers;
};

// struct cert_policies{
//     int critical;
//     STACK_OF(POLICY_INFO) *policies;
// };
// 
// struct policy_mappings{
//     int critical;
//     POLICY_MAPPINGS *mappings;
// };
union sub_dir_attrs_value{
    STACK_OF(STRING_POINTER) *str_value;
    ANY *any_value;
};


struct subject_dir_attrs{
    ASN1_OBJECT *oid;
    SUB_DIR_ATTRS_VALUE *value;
};

struct bc{
    int is_ca;
    ASN1_INTEGER *pathlen;
};

struct general_subtree{
    GENERAL_NAME_POINTER *gen_name;
    ASN1_INTEGER *min_base_distance;
    ASN1_INTEGER *max_base_distance;
};

struct name_constraints{
    STACK_OF(GENERAL_SUBTREES) *permitted_subtrees;
    STACK_OF(GENERAL_SUBTREES) *excluded_subtrees;
};

union dp{
    STACK_OF(GENERAL_NAME_POINTER) *full_name;
    X509_NAME *relative_to_crl_issuer;
};

struct dps{
    DP_NAME *dp_name;
    ASN1_STRING *reason_flags;
    STACK_OF(GENERAL_NAME_POINTER) *crl_issuer;
};

struct access_description{
    ASN1_OBJECT *access_method;
    GENERAL_NAME_POINTER access_location;
};

union x509_exts_value{
    AUTH_KEY_ID *aki;
    ASN1_OCTET_STRING *octet;
    ASN1_STRING *keyusage;
    STACK_OF(POLICY_INFO) *policies;
    POLICY_MAPPINGS *mappings;
    STACK_OF(GENERAL_NAME_POINTER) *gen_names;
    STACK_OF(SUBJECT_DIRECTORY_ATTRIBUTES) *subject_directory;
    BASIC_CONSTRAINT *basic_constraints;
    NAME_CONSTRAINT *name_constraints;
    POLICY_CONSTRAINTS *policy_constraints;
    EXTENDED_KEY_USAGE *ext_key_usage;
    STACK_OF(CRL_DISTRIBUTION_POINT) *crl_dps;
    STACK_OF(ACCESS_DESCRIPTIONS) *access_descriptions;
    ASN1_INTEGER *inhibit_any_policy;
};

struct x509_exts{
    ASN1_OBJECT *oid;
    int critical;
    X509_EXTENSION_VALUE *value;
};

struct x509_string_name{
    ASN1_OBJECT *oid;
    ASN1_STRING *value;
};

union x509_dname_entry{
    X509_STRING_NAME *string_name;
    other_name *other_name;
};

struct ci{
int version;
ASN1_INTEGER *serial_number;
ALG_ID *signature_algorithm;
STACK_OF(X509_DNAME_ENTRY) *issuer;
X509_VAL *validity;
STACK_OF(X509_DNAME_ENTRY) *subject;
PUBKEY_ALG *pkey;
ASN1_STRING *issuerUID;
ASN1_STRING *subjectUID;
//AUTH_KEY_ID *aki;
//CERTIFICATE_POLICIES *cert_policies;
//X509_POLICY_MAPPINGS *policy_mappings;
//SUBJECT_KEY_ID ski;
//SUBJECT_ALT_NAME *subject_alternative_name;
//SUBJECT_ALT_NAME *issuer_alternative_name;
STACK_OF(x509_EXTENSION) *extensions;
unsigned char mask;
unsigned char mask_ca;
unsigned char is_ca;
unsigned char eku_mask;
int key_id;
X509_SIGNATURE *signature;
};
