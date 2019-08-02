
This file shows how to generate, compile and run NAXiPP.

# Generate Parser

##### -----BEGIN PARSER GENERATION-----
This step is actually needed only if customizations to the
predicated grammar in file RFC5280.g are necessary. Otherwise,
just go to compilation step.
For parser generation, ANTLR parser generator and its C-backend
are used to derive the C code for Lexer and Parser, starting
from the predicated grammar definition.
First of all, ANTLR is a Java program, hence we need to include
the ANTLR classes in the Java classpath. To do this, we add the
Java archive explicitly to the CLASSPATH environment variable:

`export CLASSPATH=.:./antlr-3.5.2-complete.jar:$CLASSPATH`

Replace antlr-3.5.2-complete.jar with the actual jar of your
ANTLR installation. Then, we can generate the parser by employing
the Makefile with target gen_parser:

`make gen_parser`

Remarks:
 1. Parser generation might be memory intensive. Therefore, while
    calling ANTLR in the Makefile, 16 GB of RAM are reserved for
    the Java Virtual Machine (JVM). You may need to adjust this 
    amount of RAM with the option -Xmx[number]g to set to 
    [number] GB the amount of RAM used by the JVM.
 1. It is likely that you will observe a lot of warnings stating
    a template error. You can ignore those warnings since they
    are due to an unfixed harmless bug in ANTLR C backend

Once ANTLR stops, the Lexer and Parser source and header files
should have been generated. You can now proceed to the
compilation of the parser
##### -----END PARSER GENERATION-----

# Compile Parser

##### -----BEGIN COMPILING-----
To compile the parser, You can simply run `make` command with default
target. clang compiler is the default choice, but it can be changed
by modifying the `CC` variable in the Makefile. Please, be sure that 
all the header files and the dynamic libraries needed by the parser 
(which can be found in the README file) can be found, setting the 
`INCLUDE_DIR` and `LIB_DIR` variables if needed.

By default, `make` generates two executables, one expecting X.509 
certificates in DER format while the other one expects X.509
certificates in PEM format. To generate only one of the two executables
run, respectively, `make x509parser_der` and `make x509parser_pem`
##### -----END COMPILING-----

# Run Parser

##### -----BEGIN USAGE-----
Right now, there are two different versions of NAXiPP.

 1. `x509parser_pem` : The certificate to be parsed is provided
as the first command line argument to the executable, in PEM format 
with no newlines (see example pem certificates). For instance,
assuming we want to parse the example certificate 
`KeycertSignNoBC_no_nl.pem`, the parser is invoked by:

`./x509parser_pem $(cat KeycertSignNoBC_no_nl.pem)`

 2. `x509parser_der` : The path of the file storing the certificate 
in DER format is the first command line argument to the executable.
For instance, assuming we want to parse the example certificate 
`hugeGenNames.der`, the parser is invoked by:

`./x509parser_der hugeGenNames.der`

In both cases, the outcome of parsing is the exit code. A zero value
means that the certificate is valid, while a non-zero value is
returned is a syntactical error is found. The meaning of the different
error codes can be found in RFC5280.h. Moreover, an integer value
representing a warning message is printed to stdout. The meaning
of the different warning codes can be found in RFC5280.h. Note that
a warning usually is an issue found in the certificate which however
does not prevent its recognition. Nevertheless, warnings can be
really important, so You should not ignore the issue being reported.
##### -----END USAGE-----
