#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>

#define BUFFER_SIZE 1024

SSL_CTX *create_client_context() {
    SSL_CTX *ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_client_context(SSL_CTX *ctx) {
    if (SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs") <= 0) {
        perror("Unable to set verify location");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void *receive_messages(void *arg) {
    SSL *ssl = (SSL *)arg;
    char buffer[BUFFER_SIZE];
    int bytes;

    while ((bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes] = '\0';
        printf("Received: %s\n", buffer);
    }

    return NULL;
}

//Debut Interface pour le transfert de fichier
void send_file(SSL *ssl, char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Unable to open file");
        return;
    }

    char buffer[BUFFER_SIZE];
    int bytes;

    while ((bytes = fread(buffer, sizeof(char), sizeof(buffer), file)) > 0) {
        SSL_write(ssl, buffer, bytes);
    }

    fclose(file);
}
//Fin Interface pour le transfert de fichier

void *send_messages(void *arg) {
    SSL *ssl = (SSL *)arg;
    char buffer[BUFFER_SIZE];
    int bytes;

    while (1) {
        printf("Saisir : ");
        fgets(buffer, sizeof(buffer), stdin);
        buffer[strcspn(buffer, "\n")] = '\0'; // Supprimer le retour à la ligne

        if (strncmp(buffer, "/creergroupe ", 13) == 0) {
            SSL_write(ssl, buffer, strlen(buffer));
        } else if (strncmp(buffer, "/rejoindregroupe ", 6) == 0) {
            SSL_write(ssl, buffer, strlen(buffer));
        } else if (strncmp(buffer, "/messagegroupe ", 5) == 0) {
            SSL_write(ssl, buffer, strlen(buffer));
        } else if (strncmp(buffer, "/envoiefichier ", 10) == 0) {
            char *filename = buffer + 10;
            send_file(ssl, filename);
        } else {
            SSL_write(ssl, buffer, strlen(buffer));
        }
    }

    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <server_ip> <server_port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *server_ip = argv[1];
    int server_port = atoi(argv[2]);

    SSL_CTX *ctx;
    SSL *ssl;
    int server_fd;
    struct sockaddr_in server_addr;
    pthread_t receive_tid, send_tid;

    // Initialisation d'OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Création du contexte SSL client
    ctx = create_client_context();

    // Configuration du contexte SSL client
    configure_client_context(ctx);

    // Création de la socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    // Configuration de l'adresse du serveur
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        exit(EXIT_FAILURE);
    }

    // Connexion au serveur
    if (connect(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection Failed");
        exit(EXIT_FAILURE);
    }

    // Création de l'objet SSL et l'associer à la socket
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_fd);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    printf("Connecté au serveur, vous pouvez utiliser les commandes suivantes :.\n");
    printf("Envoyer un Message : Tapez votre message et appuyez sur Entrée\n");
    printf("Créer un Groupe : Utilisez la commande '/creergroupe <nom_du_groupe>'\n");
    printf("Rejoindre un Groupe : Utilisez la commande '/rejoindregroupe <nom_du_groupe>'\n");
    printf("Envoyer un Message à un Groupe : Utilisez la commande '/messagegroupe <nom_du_groupe> <message>'\n");
    printf("Transférer un Fichier : Utilisez la commande '/envoiefichier <chemin_du_fichier>'\n");


    // Création des threads pour la réception et l'envoi de messages
    if (pthread_create(&receive_tid, NULL, receive_messages, (void *)ssl) != 0) {
        perror("Unable to create receive thread");
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&send_tid, NULL, send_messages, (void *)ssl) != 0) {
        perror("Unable to create send thread");
        exit(EXIT_FAILURE);
    }

    // Attente de la fin des threads
    pthread_join(receive_tid, NULL);
    pthread_join(send_tid, NULL);

    // Nettoyage
    SSL_shutdown(ssl);
    close(server_fd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}
