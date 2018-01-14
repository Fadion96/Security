#ifndef SIGNATURER_BSERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <gnome-keyring.h>
#include <gnome-keyring-memory.h>
#include <gnome-keyring-result.h>
#include <glib.h>
//#include <libsecret/secret.h>



#define BUFFER_SIZE 4096
#define LENGTH 32
#define ITERS 5000
#define HASH_LEN 16
#define SIGNATURER_BSERVER_H
//#define EXAMPLE_SCHEMA  example_get_schema ()
//const SecretSchema * example_get_schema (void) G_GNUC_CONST;


    RSA *r ;
    BIGNUM *num, *N, *d;
    BN_CTX *ctx;            //for BIGNUM temp variables used by library functions
    int ret;
    char pass[1024];

    static void creat_item_cb  (GnomeKeyringResult result, guint32 id, gpointer data);
    static void create_item (char *name,char *name2, char *attr_name, gboolean update_if_exists);
    static void print_attributes (GnomeKeyringAttributeList *attributes);
    static void find_items_cb (GnomeKeyringResult result, GList *found_items, gpointer date);
    static void find_items (char *attr_val);

    void setup(char* path);
    void generate_password();
    unsigned char* generate_random_bytes(int size);
    char* code_base64(unsigned char *buff, int size);
    void generate_key_pair(int key_length, char *path_to_save);
    void communicate_with_client(char *password, int port, char *key_path);
    int is_server_password_valid(char *user_pass);
    void read_key_from_file(char *path);
    int is_msg_in_group(BIGNUM *num);
    char* sign_msg(BIGNUM *msg);

    //~bserver();



#endif //SIGNATURER_BSERVER_H
