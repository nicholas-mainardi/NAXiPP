This file shows how to generate, compile and run NAnoXiPP.

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
ANTLR installation. Then, we can invoke ANTLR with the following
command:

`java org.antlr.Tool RFC5280.g`

Remarks:
 1. parser generation might be memory intensive. Therefore, You 
    may need to add the option -Xmx[number]g to increase to 
    [number] GB the amount of RAM used by the Java Virtual 
    Machine(JVM).
 1. It is likely that You will observe a lot of warnings stating
    a template error. You can ignore those warnings since they
    are due to an unfixed harmless bug in ANTLR C backend

Once ANTLR stops, the Lexer and Parser source and header files
should have been generated. You can now proceed to the
compilation of the parser
##### -----END PARSER GENERATION-----

# Compile Parser

##### -----BEGIN COMPILING-----
To compile the parser, You can simply use gcc or clang to compile
3 source files: lexer, parser and main. Refer to the Makefile,
in particular to x509parser target, to see an example of the
compiler invocation. Please, be sure that all the dynamic libraries
needed by the parser (which can be found in the README file) are 
installed on the system where the parser is compiled.
##### -----END COMPILING-----

# Run Parser

##### -----BEGIN USAGE-----
Right now, there are different interfaces to X.509ParSec,
depending on which main file You compile.

 1. RFC5280MainArgv.c : The certificate to be parsed is provided
as the first command line argument to the executable, in PEM format 
with no newlines (see example pem certificates). For instance,
assuming we want to parse the example certificate 
"KeycertSignNoBC_no_nl.pem" and the executable name is x509parser,
the parser is invoked by:

`./x509parser $(cat KeycertSignNoBC_no_nl.pem)`

 1. RFC5280MainFile.c : The path of the file storing the certificate 
in DER format is the first command line argument to the executable.
For instance, assuming we want to parse the example certificate 
"hugeGenNames.der" and the executable name is x509parser, the parser
is inovked by:

`./x509parser hugeGenNames.der`

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
