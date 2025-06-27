/*
* Protocoale de comunicatii
* Laborator 9 - HTTP
* requests.cpp
* https://pcom.pages.upb.ro/labs/lab9/http_req.html
*/
#include <stdlib.h> /* exit, atoi, malloc, free */
#include <stdio.h>
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include <iostream>
#include <vector>
#include "helpers.hpp"
#include "requests.hpp"

/**
 * @brief Build a complete HTTP GET request message.
 *
 * Builds the request line, Host header, optional Cookie and
 * Authorization headers, then terminates headers.
 *
 * @param host The target server hostname.
 * @param url The resource path (URL) to request.
 * @param query_params  Optional query string or nullptr.
 * @param cookies Vector of C-string cookies to include.
 * @param cookies_count Number of cookies in the vector.
 * @param token Token for authorization header.
 * @return Newly allocated C-string containing the full HTTP GET request.
 */
char *compute_get_request(const char *host,
						  const char *url,
						  const char *query_params,
						  const std::vector<char *> &cookies,
						  int cookies_count,
						  const char *token)
{
	char *message = (char *)calloc(BUFLEN, 1);
	char *line = (char *)calloc(LINELEN, 1);

	// Request line
	if (query_params) {
		sprintf(line, "GET %s?%s HTTP/1.1", url, query_params);
	} else {
		sprintf(line, "GET %s HTTP/1.1", url);
	}
	compute_message(message, line);

	// Host header
	sprintf(line, "Host: %s", host);
	compute_message(message, line);

	// Cookie header
	if (cookies_count > 0) {
		// Clear the line buffer
		memset(line, 0, LINELEN);
		strcat(line, "Cookie: ");
		// Concatenate all cookies
		for (int i = 0; i < cookies_count; ++i) {
			strcat(line, cookies[i]);
			if (i + 1 < cookies_count)
				strcat(line, "; ");
		}
		compute_message(message, line);
	}

	// Authorization header
	if (token && *token) {
		snprintf(line, LINELEN, "Authorization: Bearer %s", token);
		compute_message(message, line);
	}

	// End of headers
	compute_message(message, "");

	free(line);
	return message;
}

/**
 * @brief Build a complete HTTP POST request message.
 *
 * Creates an HTTP request with headers (Host, Content-Type, Content-Length),
 * optional Bearer token, cookies, and body.
 *
 * @param host The target server hostname.
 * @param url The resource path (URL) to request.
 * @param query_params  Optional query string or nullptr.
 * @param cookies Vector of C-string cookies to include.
 * @param cookies_count Number of cookies in the vector.
 * @param token Token for authorization header.
 * @return Newly allocated C-string containing the full HTTP POST request.
 */
char *compute_post_request(const char *host,
						   const char *url,
						   const char *content_type,
						   char **body_data,
						   int body_data_fields_count,
						   const std::vector<char *> &cookies,
						   int cookies_count,
						   const char *token)
{
	char *message = (char *)calloc(BUFLEN, 1);
	char *line = (char *)calloc(LINELEN, 1);
	char *body_buffer = (char *)calloc(LINELEN, 1);

	// Request line
	sprintf(line, "POST %s HTTP/1.1", url);
	compute_message(message, line);

	// Host header
	sprintf(line, "Host: %s", host);
	compute_message(message, line);

	// Content-Type and Content-Length
	sprintf(line, "Content-Type: %s", content_type);
	compute_message(message, line);
	int content_length = 0;
	for (int i = 0; i < body_data_fields_count; ++i) {
		content_length += strlen(body_data[i]);
		// Add 1 for '&' between fields
		if (i + 1 < body_data_fields_count)
			content_length += 1; // '&'
	}
	sprintf(line, "Content-Length: %d", content_length);
	compute_message(message, line);

	// Concatenate body_data into body_buffer
	for (int i = 0; i < body_data_fields_count; ++i) {
		strcat(body_buffer, body_data[i]);
		if (i + 1 < body_data_fields_count)
			strcat(body_buffer, "&");
	}

	// Cookie header
	if (cookies_count > 0) {
		memset(line, 0, LINELEN);
		strcat(line, "Cookie: ");
		for (int i = 0; i < cookies_count; ++i) {
			strcat(line, cookies[i]);
			if (i + 1 < cookies_count)
				strcat(line, "; ");
		}
		compute_message(message, line);
	}

	// Authorization header
	if (token && *token) {
		snprintf(line, LINELEN, "Authorization: Bearer %s", token);
		compute_message(message, line);
	}

	// End of headers
	compute_message(message, "");

	// Body
	strcat(message, body_buffer);

	free(line);
	free(body_buffer);
	return message;
}

/**
 * @brief Build a complete HTTP DELETE request message.
 *
 * Assembles the DELETE line, Host header,
 * optional Cookie and Authorization headers,
 * then terminates headers.
 *
 * @param host The target server hostname.
 * @param url The resource path (URL) to request.
 * @param query_params  Optional query string or nullptr.
 * @param cookies Vector of C-string cookies to include.
 * @param cookies_count Number of cookies in the vector.
 * @param token Token for authorization header.
 * @return Newly allocated C-string containing the full HTTP DELETE request.
 */
char *compute_delete_request(const char *host,
							 const char *url,
							 const std::vector<char *> &cookies,
							 int cookies_count,
							 const char *jwt_token)
{
	char *message = (char *)calloc(BUFLEN, sizeof(char));
	char *line = (char *)calloc(LINELEN, sizeof(char));

	// Request line
	sprintf(line, "DELETE %s HTTP/1.1", url);
	compute_message(message, line);

	// Host header
	sprintf(line, "Host: %s", host);
	compute_message(message, line);

	// Cookie header (if any)
	if (cookies_count > 0) {
		memset(line, 0, LINELEN);
		strcat(line, "Cookie: ");
		// Concatenate all cookies
		for (int i = 0; i < cookies_count; ++i) {
			strcat(line, cookies[i]);
			// Add a semicolon between cookies
			if (i + 1 < cookies_count)
				strcat(line, "; ");
		}
		compute_message(message, line);
	}

	// Authorization header (if JWT present)
	if (jwt_token && *jwt_token) {
		snprintf(line, LINELEN, "Authorization: Bearer %s", jwt_token);
		compute_message(message, line);
	}

	// End of headers
	compute_message(message, "");

	free(line);
	return message;
}

/**
 * @brief Build a complete HTTP PUT request message.
 *
 * Assembles the PUT line, Host, Content-Type,
 * Content-Length, optional Cookie and Authorization headers,
 * then appends the body.
 *
 * @param host The target server hostname.
 * @param url The resource path (URL) to request.
 * @param query_params  Optional query string or nullptr.
 * @param cookies Vector of C-string cookies to include.
 * @param cookies_count Number of cookies in the vector.
 * @param token Token for authorization header.
 * @return Newly allocated C-string containing the full HTTP PUT request.
 */
char *compute_put_request(const char *host,
						  const char *url,
						  const char *content_type,
						  const char *body_data,
						  const std::vector<char *> &cookies,
						  int cookies_count,
						  const char *token)
{
	char *message = (char *)calloc(BUFLEN, 1);
	char *line = (char *)calloc(LINELEN, 1);

	// Request line
	sprintf(line, "PUT %s HTTP/1.1", url);
	compute_message(message, line);

	// Host header
	sprintf(line, "Host: %s", host);
	compute_message(message, line);

	// Content-Type + Content-Length
	sprintf(line, "Content-Type: %s", content_type);
	compute_message(message, line);
	sprintf(line, "Content-Length: %zu", strlen(body_data));
	compute_message(message, line);

	// Cookie header
	if (cookies_count > 0) {
		memset(line, 0, LINELEN);
		strcat(line, "Cookie: ");
		// Concatenate all cookies
		for (int i = 0; i < cookies_count; ++i) {
			strcat(line, cookies[i]);
			// Add a semicolon between cookies
			if (i + 1 < cookies_count)
				strcat(line, "; ");
		}
		compute_message(message, line);
	}

	// Authorization header
	if (token && *token) {
		snprintf(line, LINELEN, "Authorization: Bearer %s", token);
		compute_message(message, line);
	}

	// End of headers
	compute_message(message, "");

	// Body
	strcat(message, body_data);

	free(line);
	return message;
}
