#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 12345
#define MAX_CLIENTS 10
#define MAX_GROUPS 10 // Ajout de la définition de MAX_GROUPS
#define BUFFER_SIZE 1024

typedef struct {
    SSL *ssl;
    struct sockaddr_in addr;
    int id; // Identifiant unique du client
} connection_t;

typedef struct {
    connection_t *clients[MAX_CLIENTS];
    int client_count;
    pthread_mutex_t mutex;
} server_t;

server_t server;

// Debut Structure pour les groupes
typedef struct {
    char name[50];
    connection_t *members[MAX_CLIENTS];
    int member_count;
} group_t;

group_t groups[MAX_GROUPS];
int group_count = 0;
// Fin Structure pour les groupes


SSL_CTX *create_server_context() {
    SSL_CTX *ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_server_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

// Ajoutez des fonctions pour un groupe
void create_group(char *group_name) {
    pthread_mutex_lock(&server.mutex);
    strcpy(groups[group_count].name, group_name);
    groups[group_count].member_count = 0;
    group_count++;
    pthread_mutex_unlock(&server.mutex);
}

void add_member_to_group(char *group_name, connection_t *member) {
    pthread_mutex_lock(&server.mutex);
    for (int i = 0; i < group_count; i++) {
        if (strcmp(groups[i].name, group_name) == 0) {
            groups[i].members[groups[i].member_count++] = member;
            break;
        }
    }
    pthread_mutex_unlock(&server.mutex);
}

void send_message_to_group(char *group_name, char *message, connection_t *sender) {
    pthread_mutex_lock(&server.mutex);
    for (int i = 0; i < group_count; i++) {
        if (strcmp(groups[i].name, group_name) == 0) {
            for (int j = 0; j < groups[i].member_count; j++) {
                if (groups[i].members[j] != sender) {
                    SSL_write(groups[i].members[j]->ssl, message, strlen(message));
                }
            }
            break;
        }
    }
    pthread_mutex_unlock(&server.mutex);
}
// Fin fonctionnalités groupe

// Fonctionnalité de transfert de fichiers
void receive_file(SSL *ssl, char *filename) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Unable to open file");
        return;
    }

    char buffer[BUFFER_SIZE];
    int bytes;

    while ((bytes = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
        fwrite(buffer, sizeof(char), bytes, file);
    }

    fclose(file);
}
// Fin fonctionnalité de transfert de fichier

void *handle_client(void *arg) {
    connection_t *connection = (connection_t *)arg;
    SSL *ssl = connection->ssl;
    char buffer[BUFFER_SIZE];
    int bytes;

    while ((bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes] = '\0'; // Terminer la chaîne
       

        // Gérer les commandes de groupe et les transferts de fichiers :
        if (strncmp(buffer, "/creergroupe ", 13) == 0) {
            create_group(buffer + 13);
        } else if (strncmp(buffer, "/rejoindregroupe ", 6) == 0) {
            add_member_to_group(buffer + 6, connection);
        } else if (strncmp(buffer, "/messagegroupe ", 5) == 0) {
            char *group_name = strtok(buffer + 5, " ");
            char *message = strtok(NULL, "");
            send_message_to_group(group_name, message, connection);
        } else if (strncmp(buffer, "/envoiefichier ", 10) == 0) {
            char *filename = buffer + 10;
            receive_file(ssl, filename);
        } else {

            // Envoyer le message à tous les autres clients
            pthread_mutex_lock(&server.mutex);
            for (int i = 0; i < server.client_count; ++i) {
                connection_t *client = server.clients[i];
                if (client != connection) {
                    SSL_write(client->ssl, buffer, strlen(buffer));
                }
            }
            pthread_mutex_unlock(&server.mutex);
        }
    }

    // Fermeture de la connexion
    SSL_shutdown(ssl);
    close(SSL_get_fd(ssl));

    // Supprimer le client de la liste
    pthread_mutex_lock(&server.mutex);
    for (int i = 0; i < server.client_count; ++i) {
        if (server.clients[i] == connection) {
            memmove(&server.clients[i], &server.clients[i + 1], (server.client_count - i - 1) * sizeof(connection_t *));
            server.client_count--;
            break;
        }
    }
    pthread_mutex_unlock(&server.mutex);

    // Libérer la mémoire
    free(connection);
    pthread_exit(NULL);
}

int main() {
    SSL_CTX *ctx;
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    pthread_t tid;
    int client_id = 1; // Compteur pour attribuer un ID unique à chaque client

    // Initialisation d'OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Création du contexte SSL du serveur
    ctx = create_server_context();

    // Configuration du contexte SSL du serveur
    configure_server_context(ctx);

    // Initialisation de la structure du serveur
    server.client_count = 0;
    pthread_mutex_init(&server.mutex, NULL);

    // Création de la socket du serveur
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    // Liaison de la socket au port
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    // Écoute des connexions entrantes
    if (listen(server_fd, 5) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }
    printf("Server listening on port %d...\n", PORT);

    // Acceptation des connexions entrantes
    while (1) {
        socklen_t client_len = sizeof(client_addr);
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        // Création d'un contexte SSL pour le client
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(client_fd);
            continue;
        }

        // Gestion de la connexion client dans un thread séparé
        connection_t *connection = (connection_t *)malloc(sizeof(connection_t));
        connection->ssl = ssl;
        connection->addr = client_addr;
        connection->id = client_id++;

        pthread_mutex_lock(&server.mutex);
        if (server.client_count < MAX_CLIENTS) {
            server.clients[server.client_count++] = connection;
            if (pthread_create(&tid, NULL, handle_client, (void *)connection) != 0) {
                perror("Unable to create thread");
                close(client_fd);
                SSL_free(ssl);
                free(connection);
            }
        } else {
            printf("Too many clients. Connection rejected.\n");
            close(client_fd);
            SSL_free(ssl);
            free(connection);
        }
        pthread_mutex_unlock(&server.mutex);
    }

    // Nettoyage
    close(server_fd);
    SSL_CTX_free(ctx);
    pthread_mutex_destroy(&server.mutex);

    return 0;
}
