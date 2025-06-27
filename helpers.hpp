/*
* Protocoale de comunicatii
* Laborator 9 - HTTP
* helpers.hpp
*/
#ifndef _HELPERS_
#define _HELPERS_

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>

#define BUFLEN 4096
#define LINELEN 1000

#define BAD_REQUEST 400
#define NOT_FOUND 404
#define FORBIDDEN 403

#define LOGIN "/api/v1/tema/admin/login"
#define LOGIN_USER "/api/v1/tema/user/login"
#define USERS "/api/v1/tema/admin/users"
#define LIB_ACCESS "/api/v1/tema/library/access"
#define COLLECTIONS "/api/v1/tema/library/collections"
#define LOGOUT "/api/v1/tema/admin/logout"
#define LOGOUT_USER "/api/v1/tema/user/logout"
#define MOVIES "/api/v1/tema/library/movies"
#define PAYLOAD_TYPE "application/json"

/*
* Macro for error handling
*/
#define DIE(assertion, call_description)                       \
	do                                                         \
	{                                                          \
		if (assertion)                                         \
		{                                                      \
			fprintf(stderr, "(%s, %d): ", __FILE__, __LINE__); \
			perror(call_description);                          \
			exit(EXIT_FAILURE);                                \
		}                                                      \
	} while (0)

struct Cookies {
	std::vector<char* > admin; // for storing admin cookies
	std::vector<char* > user; // for storing user cookies
};

struct HttpResponse {
	char *raw;    // the raw response buffer containing headers and body
	int   status; // HTTP status
};

// Enum containing all possible commands
enum CommandType {
	CMD_LOGIN_ADMIN,
	CMD_ADD_USER,
	CMD_GET_USERS,
	CMD_DELETE_USER,
	CMD_LOGOUT_ADMIN,
	CMD_LOGIN,
	CMD_GET_ACCESS,
	CMD_ADD_MOVIE,
	CMD_GET_MOVIES,
	CMD_GET_MOVIE,
	CMD_DELETE_MOVIE,
	CMD_LOGOUT,
	CMD_UPDATE_MOVIE,
	CMD_GET_COLLECTIONS,
	CMD_ADD_COLLECTION,
	CMD_GET_COLLECTION,
	CMD_DELETE_COLLECTION,
	CMD_ADD_MOVIE_TO_COLLECTION,
	CMD_DELETE_MOVIE_FROM_COLLECTION,
	CMD_EXIT,
	CMD_INVALID
};

// shows the current error
void error(const char *msg);

// adds a line to a string message
void compute_message(char *message, const char *line);

// opens a connection with server host_ip on port portno, returns a socket
int open_connection(const char *host_ip, int portno, int ip_type, int socket_type, int flag);

// closes a server connection on socket sockfd
void close_connection(int sockfd);

// send a message to a server
void send_to_server(int sockfd, char *message);

// receives and returns the message from a server
char *receive_from_server(int sockfd);

// extracts and returns a JSON from a server response
char *basic_extract_json_response(char *str);

// checks if the HTTP status code indicates success
bool is_success(int status);

// parse a user‐typed string into one of the above
CommandType parse_command(const std::string &input);

#endif
