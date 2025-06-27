/*
 * Protocoale de comunicatii
 * Laborator 9 - HTTP
 * helpers.cpp
 */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <stdio.h>
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.hpp"
#include "buffer.hpp"

#define HEADER_TERMINATOR "\r\n\r\n"
#define HEADER_TERMINATOR_SIZE (sizeof(HEADER_TERMINATOR) - 1)
#define CONTENT_LENGTH "Content-Length: "
#define CONTENT_LENGTH_SIZE (sizeof(CONTENT_LENGTH) - 1)

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

int open_connection(const char *host_ip, int portno, int ip_type, int socket_type, int flag)
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

/*
 * @brief Check if the HTTP status code indicates success.
 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status#successful_responses
 */
bool is_success(int status) {
    return status / 100 == 2;
}

/*
 * @brief Parse a command string and return the corresponding CommandType.
 * @param s The command string to parse.
 * @return The corresponding CommandType or CMD_INVALID if not found.
 */
CommandType parse_command(const std::string &s) {
    if (s == "login_admin")                       return CMD_LOGIN_ADMIN;
    if (s == "add_user")                          return CMD_ADD_USER;
    if (s == "get_users")                         return CMD_GET_USERS;
    if (s == "delete_user")                       return CMD_DELETE_USER;
    if (s == "logout_admin")                      return CMD_LOGOUT_ADMIN;
    if (s == "login")                             return CMD_LOGIN;
    if (s == "get_access")                        return CMD_GET_ACCESS;
    if (s == "add_movie")                         return CMD_ADD_MOVIE;
    if (s == "get_movies")                        return CMD_GET_MOVIES;
    if (s == "get_movie")                         return CMD_GET_MOVIE;
    if (s == "delete_movie")                      return CMD_DELETE_MOVIE;
    if (s == "logout")                            return CMD_LOGOUT;
    if (s == "update_movie")                      return CMD_UPDATE_MOVIE;
    if (s == "get_collections")                   return CMD_GET_COLLECTIONS;
    if (s == "add_collection")                    return CMD_ADD_COLLECTION;
    if (s == "get_collection")                    return CMD_GET_COLLECTION;
    if (s == "delete_collection")                 return CMD_DELETE_COLLECTION;
    if (s == "add_movie_to_collection")           return CMD_ADD_MOVIE_TO_COLLECTION;
    if (s == "delete_movie_from_collection")      return CMD_DELETE_MOVIE_FROM_COLLECTION;
    if (s == "exit")                              return CMD_EXIT;
    return CMD_INVALID;
}
