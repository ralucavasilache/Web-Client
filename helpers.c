#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <stdio.h>
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "buffer.h"
#include "parson.h"

#define HEADER_TERMINATOR "\r\n\r\n"
#define HEADER_TERMINATOR_SIZE (sizeof(HEADER_TERMINATOR) - 1)
#define CONTENT_LENGTH "Content-Length: "
#define CONTENT_LENGTH_SIZE (sizeof(CONTENT_LENGTH) - 1)

void login_prompt(char *username, char *password) {
    printf("username=");
    fgets(username, USERNAME_LEN, stdin);
    username[strlen(username) - 1] = '\0';

    printf("password=");
    fgets(password, PASSWORD_LEN, stdin);
    password[strlen(password) - 1] = '\0';
}

void register_prompt(char *username, char *password) {
    printf("username=");
    fgets(username, USERNAME_LEN, stdin);
    username[strlen(username) - 1] = '\0';
    
    printf("password=");
    fgets(password, PASSWORD_LEN, stdin);
    password[strlen(password) - 1] = '\0';
}

void get_book_prompt(char *id) {
    printf("id=");
    scanf("%s", id);
}

void delete_book_prompt(char *id) {
    printf("id=");
    scanf("%s", id);
}

void add_book_prompt(char *title, char *author, char *genre,
                        char *publisher, char *page_count) {
    printf("title=");
    fgets(title, TITLE_LEN, stdin);
    title[strlen(title) - 1] = '\0';

    printf("author=");
    fgets(author, AUTHOR_LEN, stdin);
    author[strlen(author) - 1] = '\0';

    printf("genre=");
    fgets(genre, GENRE_LEN, stdin);
    genre[strlen(genre) - 1] = '\0';

    printf("publisher=");
    fgets(publisher, PUBLISHER_LEN, stdin);
    publisher[strlen(publisher) - 1] = '\0';

    printf("page_count=");
    fgets(page_count, PAGE_COUNT_LEN, stdin);
    page_count[strlen(page_count) - 1] = '\0';
}

char *compute_add_book_json(char *title, char *author, char *genre,
                            char *publisher, char *page_count) {
    JSON_Value *add_value = json_value_init_object();
    JSON_Object *add_object = json_value_get_object(add_value);
    json_object_set_string(add_object, "title", title);
    json_object_set_string(add_object, "author", author);
    json_object_set_string(add_object, "genre", genre);
    json_object_set_string(add_object, "publisher", publisher);
    json_object_set_string(add_object, "page_count", page_count);
    char *add_json = json_serialize_to_string(add_value);

    return add_json;
}

char *compute_register_json(char *username, char *password) {
    JSON_Value *register_value = json_value_init_object();
    JSON_Object *register_object = json_value_get_object(register_value);
    json_object_set_string(register_object, "username", username);
    json_object_set_string(register_object, "password", password);
    char *register_json = json_serialize_to_string(register_value);

    return register_json;
}

char *compute_login_json(char *username, char *password) {
    JSON_Value *login_value = json_value_init_object();
    JSON_Object *login_object = json_value_get_object(login_value);
    json_object_set_string(login_object, "username", username);
    json_object_set_string(login_object, "password", password);
    char *login_json = json_serialize_to_string(login_value);

    return login_json;
}
/*extrage cookiedin raspunsul primit de la server*/
void extract_cookie(char *server_response, char *cookie) {
    char *start = strstr(server_response, "connect");
    if (start != NULL) {
        char *end = strstr(start, ";");
        memcpy(cookie, start, end - start);
    }
}
/*extrage token din raspunsul server-ului / afiseaza mesajul de eroare primit*/
void extract_token(char *server_response, char *token) {
    char *start = strstr(server_response, "{");
    start += 10;
    char *end = strstr(start, "\"");
    memcpy(token, start, end - start);
    // daca s-a intors un mesaj de eroare -> token se reseteaza
    // si se printeaza msj-ul
    if (strcmp (token, "You are not logged in!") == 0) {
        printf("### ERROR : %s\n", token);
        memset(token, 0, TOKEN_LEN);
    } else {
        printf("### SUCCESS : You succesfully entered the library!\n");
    }
}
/*creeaza un url nou concatenand new_info la url*/
void compute_url(char *url, char *new_info, char *new_url) {
    strcpy(new_url, url);
    strcat(new_url, "/");
    strcat(new_url, new_info);
}

void parse_server_response_to_add(char *server_response) {
    char *start = strstr(server_response, "{");
    char *aux = calloc(AUXLEN, sizeof(char));
    if (start != NULL) {
        start += 10;
        char *end = strstr(start, "\"");
        memcpy(aux, start, end - start);
        // daca s-a intors un mesaj de eroare -> token se reseteaza
        // si se printeaza msj-ul
        printf("### ERROR : %s\n", aux);
        if (strcmp (aux, "Something Bad Happened") == 0) {
            printf("\nMake sure you respect this format: \n");
            printf("title: string \n"); 
            printf("author : string \n"); 
            printf("genre : string \n"); 
            printf("publisher : string \n"); 
            printf("page_count : int \n");    
        }
    } else {
        printf("### SUCCESS : The book was added to your library!\n");
    }
    free(aux);
}

void parse_server_response_to_register(char *server_response) {
    char *start = strstr(server_response, "{");
    char *aux = calloc(AUXLEN, sizeof(char));
    if (start != NULL) {
        start += 10;
        char *end = strstr(start, "\"");
        memcpy(aux, start, end - start);
        printf("### ERROR : %s\n", aux);
    } else {
        printf("### SUCCESS : Your account has been registered!\n");
    }
    free(aux);
}

void parse_server_response_to_login(char *server_response) {
    char *start = strstr(server_response, "{");
    char *aux = calloc(AUXLEN, sizeof(char));
    if (start != NULL) {
        start += 10;
        char *end = strstr(start, "\"");
        memcpy(aux, start, end - start);
        printf("### ERROR :  %s\n", aux);
    } else {
        printf("### SUCCESS : You are now logged in!\n");
    }
    free(aux);
}

void parse_server_response_to_logout(char *server_response) {
    char *start = strstr(server_response, "{");
    char *aux = calloc(AUXLEN, sizeof(char));
    if (start != NULL) {
        start += 10;
        char *end = strstr(start, "\"");
        memcpy(aux, start, end - start);
        printf("### ERROR : %s\n", aux);
    } else {
        printf("### SUCCESS : You succesfully logged out!\n");
    }
    free(aux);
}

void parse_server_response_to_get(char *server_response) {
    char *start = strstr(server_response, "[");
    char *aux = calloc(AUXLEN, sizeof(char));
    // daca s-a primit lista de carti
    if (start != NULL) {
        char *end = strstr(start, "]");
        end++;
        memcpy(aux, start, end - start);
        printf("### SUCCESS : Your books \n");
        printf("%s\n", aux);
    // daca s-a primit un mesaj de eroare
    } else {
        char *start = strstr(server_response, "{");
        start += 10;
        char *end = strstr(start, "\"");
        memcpy(aux, start, end - start);
        printf("### ERROR : %s\n", aux);
        if (strcmp(aux, "Error when decoding tokenn!") == 0) {
            printf("Try to login and enter the library first!\n");
        } else {
            printf("Enter a valid id!\n");
        }
    }
    free(aux);
}

void parse_server_response_to_delete(char *server_response) {
    char *start = strstr(server_response, "{");
    char *aux = calloc(AUXLEN, sizeof(char));
    if (start != NULL) {
        start += 10;
        char *end = strstr(start, "\"");
        memcpy(aux, start, end - start);
        printf("### ERROR : %s\n", aux);
        printf("Make sure you entered the library and introduced a valid ID!\n");
    } else {
        printf("### SUCCESS : The book was removed from your library!\n");
    }
    free(aux);
}

void error(const char *msg)
{
    perror(msg);
    exit(0);
}

void compute_message(char *message, const char *line)
{
    strcat(message, line);
    strcat(message, "\r\n");
}

int open_connection(char *host_ip, int portno, int ip_type, int socket_type, int flag)
{
    struct sockaddr_in serv_addr;
    int sockfd = socket(ip_type, socket_type, flag);
    if (sockfd < 0)
        error("ERROR opening socket");

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = ip_type;
    serv_addr.sin_port = htons(portno);
    inet_aton(host_ip, &serv_addr.sin_addr);

    /* connect the socket */
    if (connect(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR connecting");

    return sockfd;
}

void close_connection(int sockfd)
{
    close(sockfd);
}

void send_to_server(int sockfd, char *message)
{
    int bytes, sent = 0;
    int total = strlen(message);

    do
    {
        bytes = write(sockfd, message + sent, total - sent);
        if (bytes < 0) {
            error("ERROR writing message to socket");
        }

        if (bytes == 0) {
            break;
        }

        sent += bytes;
    } while (sent < total);
}

char *receive_from_server(int sockfd)
{
    char response[BUFLEN];
    buffer buffer = buffer_init();
    int header_end = 0;
    int content_length = 0;

    do {
        int bytes = read(sockfd, response, BUFLEN);

        if (bytes < 0){
            error("ERROR reading response from socket");
        }

        if (bytes == 0) {
            break;
        }

        buffer_add(&buffer, response, (size_t) bytes);
        
        header_end = buffer_find(&buffer, HEADER_TERMINATOR, HEADER_TERMINATOR_SIZE);

        if (header_end >= 0) {
            header_end += HEADER_TERMINATOR_SIZE;
            
            int content_length_start = buffer_find_insensitive(&buffer, CONTENT_LENGTH, CONTENT_LENGTH_SIZE);
            
            if (content_length_start < 0) {
                continue;           
            }

            content_length_start += CONTENT_LENGTH_SIZE;
            content_length = strtol(buffer.data + content_length_start, NULL, 10);
            break;
        }
    } while (1);
    size_t total = content_length + (size_t) header_end;
    
    while (buffer.size < total) {
        int bytes = read(sockfd, response, BUFLEN);

        if (bytes < 0) {
            error("ERROR reading response from socket");
        }

        if (bytes == 0) {
            break;
        }

        buffer_add(&buffer, response, (size_t) bytes);
    }
    buffer_add(&buffer, "", 1);
    return buffer.data;
}

char *basic_extract_json_response(char *str)
{
    return strstr(str, "{\"");
}
