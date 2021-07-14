#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"
#include "parson.h"

int main(int argc, char *argv[]) {   
    
    char command[COMMAND_LEN];
    char *message;
    char *server_response;
    char *cookie = calloc(COOKIE_LEN, sizeof(char));
    char *token = calloc(TOKEN_LEN, sizeof(char));
    char *username = calloc(USERNAME_LEN, sizeof(char));
    char *password = calloc(PASSWORD_LEN, sizeof(char));
    char *id = calloc(ID_LEN, sizeof(char));
    char *title = calloc(TITLE_LEN, sizeof(char));
    char *author = calloc(AUTHOR_LEN, sizeof(char));
    char *genre = calloc(GENRE_LEN, sizeof(char));
    char *publisher = calloc(PUBLISHER_LEN, sizeof(char));
    char *page_count = calloc(PAGE_COUNT_LEN, sizeof(char));
    
    while(1) {
        memset(command, 0, COMMAND_LEN);
        fgets(command, COMMAND_LEN, stdin);
        
        if(strcmp(command, "exit\n") == 0) {
            break;
        } else if (strcmp(command, "register\n") == 0) {
            memset(username, 0, USERNAME_LEN);
            memset(password, 0, PASSWORD_LEN);
            
            // citire date de la tastatura + memorarea lor intr-un fisier json
            register_prompt(username, password);
            char *register_json = compute_register_json(username, password);

            // mesajul trimis catre server
            message = compute_post_request("34.118.48.238", "/api/v1/tema/auth/register",
                                            "application/json", &register_json, 1, NULL, 0, NULL);

            // trimitere mesaj
            int sockfd = open_connection("34.118.48.238", 8080, AF_INET, SOCK_STREAM, 0);
            send_to_server(sockfd, message);
            // primire si afisare raspuns
            server_response = receive_from_server(sockfd);
            parse_server_response_to_register(server_response);

            close(sockfd);
            free(message);
            free(server_response);

        } else if (strcmp(command, "login\n") == 0) {            
            memset(username, 0, USERNAME_LEN);
            memset(password, 0, PASSWORD_LEN);
            // citire date de la tastatura + memorarea lor intr-un fisier json
            login_prompt(username, password);
            char *login_json = compute_login_json(username, password);

            // mesajul trimis catre server
            message = compute_post_request("34.118.48.238", "/api/v1/tema/auth/login",
                                            "application/json", &login_json, 1, NULL, 0, NULL);

            // trimitere mesaj
            int sockfd = open_connection("34.118.48.238", 8080, AF_INET, SOCK_STREAM, 0);
            send_to_server(sockfd, message);
            // promire si afisare raspuns
            server_response = receive_from_server(sockfd);
            // extragere cookie din raspunsul serverului
            memset(cookie, 0, COOKIE_LEN);
            extract_cookie(server_response, cookie);
            // interpreteaza raspunsul server-ului
            parse_server_response_to_login(server_response);

            close(sockfd);
            free(message);
            free(server_response);
        } else if (strcmp(command, "enter_library\n") == 0) {
            message = compute_get_request("34.118.48.238", "/api/v1/tema/library/access",
                                            NULL, &cookie, 1, NULL);

            int sockfd = open_connection("34.118.48.238", 8080, AF_INET, SOCK_STREAM, 0);
            send_to_server(sockfd, message);
            // primire si afisare raspuns
            server_response = receive_from_server(sockfd);

            // extragere token
            memset(token, 0, TOKEN_LEN);
            extract_token(server_response, token);

            close(sockfd);
            free(message);
            free(server_response);

        } else if (strcmp(command, "get_books\n") == 0) {
            message = compute_get_request("34.118.48.238", "/api/v1/tema/library/books",
                                        NULL, &cookie, 1, token);

            int sockfd = open_connection("34.118.48.238", 8080, AF_INET, SOCK_STREAM, 0);
            send_to_server(sockfd, message);
            // primire si afisare raspuns
            server_response = receive_from_server(sockfd);
            parse_server_response_to_get(server_response);

            close(sockfd);
            free(message);
            free(server_response);

        } else if (strcmp(command, "get_book\n") == 0) {
            // citire id de la tastatura
            memset(id, 0, ID_LEN);
            get_book_prompt(id);
            // creeaza url nou
            char *new_url = calloc(100, sizeof(char));
            compute_url("/api/v1/tema/library/books", id, new_url);

            message = compute_get_request("34.118.48.238", new_url,
                                        NULL, &cookie, 1, token);

            int sockfd = open_connection("34.118.48.238", 8080, AF_INET, SOCK_STREAM, 0);
            send_to_server(sockfd, message);
            // primire si afisare raspuns
            server_response = receive_from_server(sockfd);
            parse_server_response_to_get(server_response);

            close(sockfd);
            free(message);
            free(server_response);
            free(new_url);
        } else if (strcmp(command, "add_book\n") == 0) {
            if (strlen(token) != 0) {

                memset(title, 0 , TITLE_LEN);
                memset(author, 0, AUTHOR_LEN);
                memset(genre, 0, GENRE_LEN);
                memset(publisher, 0, PUBLISHER_LEN);
                memset(page_count, 0, PAGE_COUNT_LEN);
                // citire date de la tastatura
                add_book_prompt(title, author, genre, publisher, page_count);
                char *add_json = compute_add_book_json(title, author, genre, publisher, page_count);

                message = compute_post_request("34.118.48.238", "/api/v1/tema/library/books",
                                                "application/json", &add_json, 1, &cookie, 1, token);

                // trimitere mesaj
                int sockfd = open_connection("34.118.48.238", 8080, AF_INET, SOCK_STREAM, 0);
                send_to_server(sockfd, message);
                // primire si afisare raspuns
                server_response = receive_from_server(sockfd);
                parse_server_response_to_add(server_response);

                close(sockfd);
                free(message);
                free(server_response);
            } else {
                printf("### ERROR : Access denied!\n");
            }

        } else if (strcmp(command, "delete_book\n") == 0) {
            // citire id
            memset(id, 0, ID_LEN);
            delete_book_prompt(id);
            // creeaza url nou
            char *new_url = calloc(100, sizeof(char));
            compute_url("/api/v1/tema/library/books", id, new_url);

            message = compute_delete_request("34.118.48.238", new_url,
                                        NULL, &cookie, 1, token);

            int sockfd = open_connection("34.118.48.238", 8080, AF_INET, SOCK_STREAM, 0);
            send_to_server(sockfd, message);
            // primire si afisare raspuns
            server_response = receive_from_server(sockfd);
            parse_server_response_to_delete(server_response);

            close(sockfd);
            free(message);
            free(server_response);
            free(new_url);

        } else if (strcmp(command, "logout\n") == 0) {
            message = compute_get_request("34.118.48.238", "/api/v1/tema/auth/logout",
                                        NULL, &cookie, 1, token);
            
            int sockfd = open_connection("34.118.48.238", 8080, AF_INET, SOCK_STREAM, 0);
            send_to_server(sockfd, message);
            // primire si afisare raspuns
            server_response = receive_from_server(sockfd);
            parse_server_response_to_logout(server_response);
            // resetare cookie si token
            memset(cookie, 0, COOKIE_LEN);
            memset(token, 0, TOKEN_LEN);

            close(sockfd);
            free(message);
            free(server_response);
        } else {
            printf("Invalid command!\n");
        }
    }

    free(cookie);
    free(token);
    free(username);
    free(id);
    free(title);
    free(author);
    free(genre);
    free(publisher);
    free(page_count);
    return 0;
}
