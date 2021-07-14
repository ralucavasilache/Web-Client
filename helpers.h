#ifndef _HELPERS_
#define _HELPERS_

#define BUFLEN 4096
#define LINELEN 1000

#define COMMAND_LEN 50
#define USERNAME_LEN 50
#define PASSWORD_LEN 50
#define COOKIE_LEN 500
#define TOKEN_LEN 500
#define ID_LEN 10
#define TITLE_LEN 100
#define AUTHOR_LEN 100
#define GENRE_LEN 100
#define PUBLISHER_LEN 100
#define PAGE_COUNT_LEN 10
#define AUXLEN 100

// shows the current error
void error(const char *msg);

// adds a line to a string message
void compute_message(char *message, const char *line);

// opens a connection with server host_ip on port portno, returns a socket
int open_connection(char *host_ip, int portno, int ip_type, int socket_type, int flag);

// closes a server connection on socket sockfd
void close_connection(int sockfd);

// send a message to a server
void send_to_server(int sockfd, char *message);

// receives and returns the message from a server
char *receive_from_server(int sockfd);

// extracts and returns a JSON from a server response
char *basic_extract_json_response(char *str);

void login_prompt(char *username, char *password);
void register_prompt(char *username, char *password);
void get_book_prompt(char *id);
void delete_book_prompt(char *id);
void add_book_prompt(char *title, char *author, char *genre,
                        char *publisher, char *page_count);
char *compute_add_book_json(char *title, char *author, char *genre,
                            char *publisher, char *page_count);
char *compute_register_json(char *username, char *password);
char *compute_login_json(char *username, char *password);
void extract_cookie(char *server_response, char *cookie);
void extract_token(char *server_response, char *token);
void compute_url(char *url, char *new_info, char *new_url);
void parse_server_response_to_add(char *server_response);
void parse_server_response_to_register(char *server_response);
void parse_server_response_to_login(char *server_response);
void parse_server_response_to_logout(char *server_response);
void parse_server_response_to_get(char *server_response);
void parse_server_response_to_delete(char *server_response);

#endif
