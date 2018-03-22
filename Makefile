CC=clang
CFLAGS= -O2 -march=native -I../include -w
LFLAGS= -L../lib -lantlr3c -lgmp -lcrypto -lpcre2-8

#Uncomment this to proivde input certificates in PEM format
#TARGETS=RFC5280Lexer.o RFC5280Parser.o RFC5280mainPem.o

#Uncomment this to provide input certificates in DER format
#TARGETS=RFC5280Lexer.o RFC5280Parser.o RFC5280mainDer.o

all: x509parser
	clang $(LFLAGS) $(TARGETS) -o x509parser
x509parser: $(TARGETS) 

clean:
	rm -f x509parser $(TARGETS) RFC5280Lexer.c RFC5280Parser.c
	
	java -Xmx16g org.antlr.Tool RFC5280.g
