
#include "bserver.h"

static GMainLoop *loop = NULL;



static void creat_item_cb  (GnomeKeyringResult result, guint32 id, gpointer data) {
    //g_print ("created item: res: %d id: %d\n", result, id);
    g_main_loop_quit (loop);
}

static void create_item (char *name, char *name2 ,char *attr_name, gboolean update_if_exists) {
    GnomeKeyringAttributeList *attributes;
    GnomeKeyringAttribute attribute;

    attribute.name = g_strdup("testattribute");
    attribute.type = GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;
    attribute.value.string = g_strdup(attr_name);

    attributes = gnome_keyring_attribute_list_new();
    g_array_append_val(attributes, attribute);

    gnome_keyring_item_create(NULL,
                              GNOME_KEYRING_ITEM_NOTE,
                              name2,
                              attributes,
                              name,
                              update_if_exists,
                              creat_item_cb, NULL, NULL);
    gnome_keyring_attribute_list_free(attributes);
    g_main_loop_run(loop);
}

static void print_attributes (GnomeKeyringAttributeList *attributes) {
    GnomeKeyringAttribute *array;
    int i;

    array = (GnomeKeyringAttribute *)attributes->data;
    g_print (" Attributes:\n");
    for (i = 0; i < attributes->len; i++) {
        if (array[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING) {
            g_print ("  %s = '%s'\n", array[i].name, array[i].value.string);
        } else if (array[i].type == GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32) {
            g_print ("  %s = %u\n", array[i].name, array[i].value.integer);
        } else {
            g_print ("  %s = ** unsupported attribute type **\n", array[i].name);
        }
    }
}

static void find_items_cb (GnomeKeyringResult result, GList *found_items, gpointer date) {
    //g_print ("found items: res: %d nr items: %d\n", result, g_list_length (found_items));

    if (found_items != NULL) {
        GnomeKeyringFound *found = found_items->data;

        //g_print ("Found item: keyring=%s, id=%d, secret='%s'\n", found->keyring, found->item_id, found->secret);
        strncpy (pass, found->secret, strlen(found->secret));
        //print_attributes (found->attributes);
    }

    g_main_loop_quit (loop);
}

static void find_items (char *attr_val) {
    gnome_keyring_find_itemsv (GNOME_KEYRING_ITEM_NOTE,
                               find_items_cb, NULL, NULL,
                               "testattribute", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING, attr_val,
                               NULL);
    g_main_loop_run (loop);
}

void setup(char* path) {
    // Generate rsa key
    ret = BN_set_word(num, RSA_F4);         //num == e
    if(ret != 1) {
        printf("Error. Ending\n");
    }

    generate_password();

    // Generate key pairs
    generate_key_pair(2048, path);
    //generate_key_pair(4096, path);
    //generate_key_pair(8192, path);
    //generate_key_pair(16384, path);
}

void generate_password() {
    unsigned char *p = generate_random_bytes(LENGTH);
    char *password = code_base64(p, LENGTH);
    printf("Generated pass: %s\n",password);
    unsigned char *s = generate_random_bytes(LENGTH);
    char *salt = code_base64(s, LENGTH);
    unsigned char out[HASH_LEN];
    memset(out, 0, sizeof out);

    if(PKCS5_PBKDF2_HMAC(password, LENGTH, (const unsigned char *)salt, LENGTH, ITERS, EVP_sha256(), HASH_LEN, out) != 1) {
        printf("Failure\n");
    }

    char *key = code_base64(out, HASH_LEN);
    create_item (key,"Password","password", TRUE);
    printf("Password saved successfully %s \n",key);
    create_item (salt,"Salt","salt", TRUE);
    printf("Salt saved successfully %s \n",salt);
}

unsigned char* generate_random_bytes(int size) {
    unsigned char* *buff = (unsigned char*)(malloc(size + 1));

    if (!RAND_bytes(buff, size)) {
        return NULL;
    }

    return buff;
}



char* code_base64(unsigned char *buff, int size) {
    char *bytes = NULL;
    BIO *b64, *out;
    BUF_MEM *bptr;

    // Create a base64 filter/sink
    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        return NULL;
    }

    // Create a memory source
    if ((out = BIO_new(BIO_s_mem())) == NULL) {
        return NULL;
    }

    // Chain them
    out = BIO_push(b64, out);
    BIO_set_flags(out, BIO_FLAGS_BASE64_NO_NL);

    // Write the bytes
    BIO_write(out, buff, size);
    BIO_flush(out);

    // Now remove the base64 filter
    out = BIO_pop(b64);

    // Write the null terminating character
    BIO_write(out, "\0", 1);
    BIO_get_mem_ptr(out, &bptr);

    // Allocate memory for the output and copy it to the new location
    bytes = (char*)malloc(bptr->length);
    strncpy(bytes, bptr->data, bptr->length);

    // Cleanup
    BIO_set_close(out, BIO_CLOSE);
    BIO_free_all(out);
//    free(buff);

    return bytes;
}

//}

void generate_key_pair(int key_length, char* path_to_save) {
    // Measure elapsed time
    //auto start = std::chrono::high_resolution_clock::now();

    r = RSA_new();
    ret = RSA_generate_key_ex(r, key_length, num, NULL);
    if(ret != 1) {
        printf("Error. Ending\n");
    }

//    auto end = std::chrono::high_resolution_clock::now();
//    std::cout << "Generate " << key_length << " keys time: ";
//    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(end-start).count() << "ms" << std::endl;

    const BIGNUM *N = BN_new();
    const BIGNUM *d = BN_new();
    const BIGNUM *e = BN_new();
    RSA_get0_key(r, &N, &e, &d);
    char p[30];
    FILE *file;
    char *length;
    sprintf(length, "%d", key_length);
    mkdir(path_to_save,0777);

    // Save public key
    memset(p, 0, sizeof p);
    strcat(p, path_to_save);
    strcat(p, "public");
    strcat(p, length);
    file = fopen(p , "w+");
    BN_print_fp(file, N);
    fprintf(file, "\n");
    BN_print_fp(file, e);
    fclose(file);

    // Save private key
    memset(p, 0, sizeof p);
    strcat(p, path_to_save);
    strcat(p, "private");
    strcat(p, length);
    file = fopen(p , "w+");
    BN_print_fp(file, N);
    fprintf(file, "\n");
    BN_print_fp(file, d);
    fclose(file);

    printf("Key %d generated\n\n",key_length);
}

void communicate_with_client(char *password, int port, char *key_path) {
    // If pass is not correct -> end
    if(!is_server_password_valid(password)) {
        printf("Given password is not correct. Aborting...\n");
        return;
    }
    printf("Given password is correct\n\n");

    // Load proper private key (N, d)
    read_key_from_file(key_path);

    // Start server
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the given port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address))<0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("server_listen");
        exit(EXIT_FAILURE);
    }
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*) &addrlen))<0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    // Get message from client
    read(new_socket, buffer, BUFFER_SIZE);
    BIGNUM *m = BN_new();
    BN_hex2bn(&m, buffer);
    printf("Message received from the client: %s\n\n",BN_bn2hex(m));

    // If x is not in Zn group -> abort
    if(!is_msg_in_group(m)) {
        printf("Message x is not in Zn. Aborting...\n\n");
        return;
    }
    printf("Message x is in Zn.\n\n");

    // Send signed message to client
    char* signed_msg = sign_msg(m);
    printf("Signing...\n\n");
    send(new_socket, signed_msg, strlen(signed_msg), 0);
    printf("Signed msg sent to client: %s\n\n",signed_msg);
    BN_free(m);
}

int is_server_password_valid(char *user_pass) {
    char p[1024];
    unsigned char salt[1024];
    find_items("password");
    strncpy(p,pass,1024);
    find_items("salt");
    strncpy(salt,pass,1024);

    unsigned char out[HASH_LEN];
    memset(out, 0, sizeof out);

    // Hash user's pass
    if(PKCS5_PBKDF2_HMAC(user_pass, LENGTH, (const unsigned char *)salt, LENGTH, ITERS, EVP_sha256(), HASH_LEN, out) != 1) {
        printf("Failure\n");
    }

    char *key = code_base64(out, HASH_LEN);
    if(strcmp(key,p) == 0 ) {
        return 1;
    }

    return 0;
}


void read_key_from_file(char *path) {
    printf("Loading key from: %s\n",path);
    FILE *file = fopen(path, "r");
    char *line;
    size_t len = 0;
    ssize_t read;

    read = getline(&line, &len, file);
    BN_hex2bn(&N, line);
    read = getline(&line, &len, file);
    BN_hex2bn(&d, line);

//    std::cout << "N: " << BN_bn2dec(N) << std::endl << std::endl;
//    std::cout << "d: " << BN_bn2dec(d) << std::endl << std::endl;
}

int is_msg_in_group(BIGNUM *num) {
    // If num is in group -> gcd(num,N) == 1
    BIGNUM *gcd = BN_new();
    BIGNUM *one = BN_new();
    BN_gcd(gcd, num, N, ctx);
    int ret = BN_cmp(one, gcd);
    BN_free(gcd);
    BN_free(one);

    return ret != 0;
}

char* sign_msg(BIGNUM *msg_to_sign) {
    // s'= (m')^d (mod N)

    // Measure time
    //auto start = std::chrono::high_resolution_clock::now();

    BIGNUM *result = BN_new();
    BN_mod_exp(result, msg_to_sign, d, N, ctx);

//    auto end = std::chrono::high_resolution_clock::now();
//    std::cout << "Signing time: ";
//    double timer = std::chrono::duration_cast<std::chrono::microseconds>(end-start).count();
//    std::cout << timer << " us" << std::endl;


    char *ret = BN_bn2hex(result);
    BN_free(result);
    return ret;
}

//bserver::~bserver() {
//    RSA_free(r);
//    BN_free(num);
//    BN_free(N);
//    BN_free(d);
//    BN_CTX_free(ctx);
//}

int main(int argc, char*argv[]) {
    if(argc < 3) {
        printf("Missing arguments. Aborting...\n");
        return -1;
    }

    r = NULL;
    num = BN_new();
    ctx = BN_CTX_new();
    strncpy (pass, "", 1024);
    loop = g_main_loop_new (NULL, FALSE);
    if(strcmp(argv[1], "setup") == 0) {
        printf("Setup mode started\n");
        setup(argv[2]);
        return 0;
    }

    if(argc < 5) {
        printf("Missing arguments\n");
        return -1;
    }

    if(strcmp(argv[1], "sign") == 0) {
        printf("Sign mode started\n");
        communicate_with_client(argv[2], atoi(argv[3]), argv[4]);
    }
    else {
        printf("Wrong mode selected. Choose 'setup' or 'sign'\n");
    }

    return 0;
}