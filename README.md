# NAnoXiPP
NAnoXiPP - Not ANOther X509 ImProper Parser - is an automatically generated 
LL(*) parser for X.509 digital certificates. The parser is generated, 
starting from a predicated grammar, by the ANTLR 3.5 parser generator tool. 
The C backend of ANTLR 3.5 is employed. Because of design choices, the 
parser is able to recognize only digital certificates whose length is less 
than 4GB and with asymmetric encryption algorithms defined in the following 
set of complementary RFC documents:

 * RFC5758 (DSA and ECDSA)
 * RFC4055 (RSA Additional Algorithms),
 * RFC4491 (GOST suite)
 * RFC5480 (Ellyptic Curve Crypto), 
 * RFC3279 (Basic RSA, DSA, DH)  

All the details about the design of the predicated grammar will be found in
an under publication paper.

## Dependencies
##### -----BEGIN DEPENDENCIES-----
The following libraries need to be installed to compile the parser. The
version reported for each library refers to the library current used in
our environment. However, we expect that any version of these libraries
can be used.
 * antlr3c : the C backend for ANTLR 3.5
 * gmp (10.3.2) : the GNU Multi Precision library
 * pcre (10.20) : Perl Compatible Regular Expression
 * OpenSSL (1.0.2n) : OpenSSL cryptographic library (libcrypto) 
##### -----END DEPENDENCIES-----

## List of Files
##### -----BEGIN FILE LIST-----
 * `RFC5280.g` : this is the ANTLR grammar file, altogether with semantic
    actions which build the digital certificate data structure containing 
    the results of parsing.
 * `RFC5280.tokens` : file containing the list of tokens employed by the
    predicated grammar
 * `RFC5280Lexer.c` : this is the automatically generated lexer, that is
    the lexical recognizer. It basically transform a stream of bytes in
    a sequence of tokens which is later parsed
 * `RFC5280Parser.c` : this is the automatically generated parser, which
    performs syntactic validation on the sequence of tokens generated 
    by the lexer
 * `RFC5280mainPem.c` : An example main file using the lexer and parser 
    to recognize a PEM X.509 digital certificate and retrieve the digital
    certificate data structure
 * `RFC5280mainDer.c` : An example main file using the lexer and parser 
    to recognize a DER X.509 digital certificate and retrieve the digital
    certificate data structure
 * `RFC5280.h` : Header file where the syntactic error codes for the 
    parser are defined, as well as all the necessary data structures to
    store the information contained in the digital certificate
 * `Usage.md` : textual file which explains how to use the parser or to
    generate a new instance from the predicated grammar, altogether to 
    what is required or needs to be installed
 * `Makefile` : This Makefile shows how the parser generation and compilation
    can be automatized
##### -----END FILE LIST-----

## Issues and TODOs

##### -----BEGIN TODOs-----
 1. Currently, the routines to deallocate the data structures containing
    the information stored in the digital certificate are missing.
    Therefore, the parser cannot be employed to process a significant
    amount of certificates in the same process.
 1. Report more syntactic errors, even if currently 67 different errors
    reported plus a generic error
 1. Return the Abstract Syntax Tree (AST) of the parser. Consider that the 
    X.509 data structure being populated by the parser is quite close to 
    the actual AST
 1. Define a software interface to the parser which is more appropriate
    for its usage as a component of an application, and not just as a
    standalone process, which is the current usage
##### -----END TODOs-----
