EXE_PEM = x509parser_pem
EXE_DER = x509parser_der

INCLUDE_DIR = /usr/include #specify the directory where the include files can be found
LIB_DIR = /usr/lib #specify the directory where the external libraries can be found
CC=clang
CFLAGS= -O2 -march=native -I $(INCLUDE_DIR) -w 
LFLAGS= -L $(LIB_DIR) -lantlr3c -lgmp -lcrypto -lpcre2-8

SRC_DIR = gen_parser_src
GRAMMAR_DIR = Grammar

TARGETS_PEM=$(SRC_DIR)/RFC5280Lexer.o $(SRC_DIR)/RFC5280Parser.o $(SRC_DIR)/RFC5280mainPem.o

TARGETS_DER=$(SRC_DIR)/RFC5280Lexer.o $(SRC_DIR)/RFC5280Parser.o $(SRC_DIR)/RFC5280mainDer.o


all: $(EXE_PEM) $(EXE_DER)
	$(CC) $(LFLAGS) $(TARGETS_PEM) -o $(EXE_PEM)
	$(CC) $(LFLAGS) $(TARGETS_DER) -o $(EXE_DER)

$(EXE_PEM): $(TARGETS_PEM)

$(EXE_DER): $(TARGETS_DER)

clean:
	rm -f $(TARGETS_PEM) $(TARGETS_DER) $(EXE_PEM) $(EXE_DER)
gen_parser:
	rm -f $(SRC_DIR)/RFC5280Lexer.c $(SRC_DIR)/RFC5280Parser.c
	java -Xmx16g org.antlr.Tool $(GRAMMAR_DIR)/RFC5280.g
	mv $(GRAMMAR_DIR)/*.c $(GRAMMAR_DIR)/*.h $(SRC_DIR)/
	mv RFC5280.tokens $(GRAMMAR_DIR)/
