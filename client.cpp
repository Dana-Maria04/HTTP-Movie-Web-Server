/*
* Protocoale de comunicatii
* Laborator 9 - HTTP
* client.cpp
*/
#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include <iostream>
#include <string>
#include <vector>
#include <unordered_set>
#include <algorithm>
#include <map>
#include "json.hpp"
#include "helpers.hpp"
#include "requests.hpp"
#include "buffer.hpp"

const char *host = "63.32.125.183";
const int port = 8081;

/**
 * @brief Extracts the first cookie value from an HTTP response.
 *
 * Scans the raw response for a "Set-Cookie: " header, then
 * captures the cookie up to the first ';' or CRLF, allocates
 * space, copies it into cookies[*cookie_count] and increments
 * cookie_count.
 *
 * @param response HTTP response string.
 * @param cookies Array of char* to store found cookies.
 * @param cookie_count int holding current count;
 * @return Pointer to the newly allocated cookie string, or nullptr
 *         if no Set-Cookie header was found.
 */
char *extract_cookie(char *response, char **cookies, int *cookie_count)
{
	// Put the response in a buffer 
	buffer buf;
	buf.data = response;
	buf.size = strlen(response);

	// Find the "Set-Cookie" header
	const char *hdr = "Set-Cookie: ";
	int off = buffer_find_insensitive(&buf, hdr, strlen(hdr));
	DIE(off < 0, "buffer_find_insensitive");

	// Move past the header
	buffer rest;
	rest.data = buf.data + off + strlen(hdr);
	rest.size = buf.size - (off + strlen(hdr));

	// Find the end of the cookie
	int end = buffer_find(&rest, ";", 1);
	if (end < 0) {
		// If no ';' found, look for CRLF
		end = buffer_find(&rest, "\r\n", 2);
		DIE(end < 0, "buffer_find");
	}

	// Allocate space for the cookie
	char *tok = (char*)calloc(end + 1, 1);
	DIE(!tok, "calloc");
	memcpy(tok, rest.data, end);

	// Null-terminate the string
	cookies[*cookie_count] = tok;
	(*cookie_count)++;
	return tok;
}

/**
 * @brief Extracts the JSON field "token" value from an HTTP body.
 *
 * Scans the raw response for the substring "\"token\"", skips past
 * the colon and any whitespace/quotes, then copies up to the next
 * closing quote.
 *
 * @param response HTTP response containing JSON.
 * @return Newly allocated C-string with the token value, or nullptr
 *         if not found.
 */
inline char *extract_token(char *response)
{
	// Put the response in a buffer
	buffer buf;
	buf.data = response;
	buf.size = strlen(response);

	const char *key = "\"token\"";
	// Find the "token" key
	int off = buffer_find(&buf, key, strlen(key));
	DIE(off < 0, "buffer_find");

	// Move past the key
	buffer rest;
	rest.data = buf.data + off + strlen(key);
	rest.size = buf.size - (off + strlen(key));

	// Find the colon
	int colon = buffer_find(&rest, ":", 1);
	DIE(colon < 0, "buffer_find");
	// Move past the colon
	rest.data += colon + 1;
	rest.size -= colon + 1;

	while (rest.size && (*rest.data == ' ' || *rest.data == '\"')) {
		// Skip whitespace and quotes
		rest.data++;
		rest.size--;
	}

	int end = buffer_find(&rest, "\"", 1);
	// If no closing quote, look for CRLF
	DIE(end < 0, "buffer_find");

	// Allocate space for the token and copy it
	char *tok = (char*)calloc(end + 1, 1);
	DIE(!tok, "calloc");
	memcpy(tok, rest.data, end);
	return tok;
}

/**
 * @brief Sends a request over an already-open socket and closes it.
 *
 * Calls send_to_server(), then receive_from_server() to get the full
 * response, closes the socket, parses the HTTP status code from
 * the start of the response, and returns both raw response and code.
 *
 * @param sockfd File descriptor of an open, connected socket.
 * @param request HTTP request string.
 * @return An HttpResponse struct containing raw response and status code.
 */
static HttpResponse send_request(int sockfd, char *request)
{
	// Send the request to the server
	send_to_server(sockfd, request);
	char *resp = receive_from_server(sockfd);
	DIE(!resp, "receive_from_server");
	close_connection(sockfd);

	// Parse the response to get the status code
	int code = 0;
	sscanf(resp, "HTTP/%*s %d", &code);
	
	// Return the response and code 
	return {resp, code};
}

/**
 * @brief Reads a sequence of named fields from stdin.
 *
 * For each name in field names it prints "name=" and waits for a line
 * on stdin, collecting all inputs into a vector<string> in the same
 * order as field names.
 *
 * @param names List of prompts to show (e.g. {"username","password"}).
 * @return Vector of entered strings.
 */
std::vector<std::string> read_fields(const std::vector<std::string> &names)
{
	std::vector<std::string> vals;
	// Print each name and read input
	for (auto &n : names) {
		std::cout << n << "=" << std::flush;
		std::string tmp;
		std::getline(std::cin, tmp);
		vals.push_back(std::move(tmp));
	}
	return vals;
}

/**
 * @brief Frees the dynamically allocated request, response, and body.
 *
 * @param request Pointer returned by compute_*_request().
 * @param resp    Pointer returned by receive_from_server().
 * @param body    Pointer to JSON payload buffer.
 */
void cleanup(char *request, char *resp, char *body = nullptr)
{
	if (request)
		free(request);
	if (resp)
		free(resp);
	if (body)
		free(body);
}

/**
 * @brief Validates if a string is a valid numeric ID.
 *
 * Checks if the string is not empty and contains only digits.
 *
 * @param id The string to validate.
 * @return true if valid, false otherwise.
 */
static bool validate_numeric_id(const std::string &id)
{
	if (id.empty() || !std::all_of(id.begin(), id.end(), ::isdigit)) {
		// Check if the string is empty or contains non-digit characters
		std::cout << "ERROR: Invalid ID" << "\n";
		return false;
	}
	return true;
}

/**
 * @brief Validates if a string is a valid decimal number.
 *
 * Checks if the string is not empty and contains only digits and at most one dot.
 *
 * @param str The string to validate.
 * @return true if valid, false otherwise.
 */
static bool validate_decimal(const std::string &str)
{
	// Check if the string is empty
	if (str.empty()) {
		std::cout << "ERROR: Invalid value" << "\n";
		return false;
	}

	// Check if the string contains only digits and at most one dot
	int dot_count = 0;
	for (char c : str) {
		if (c == '.') {
			dot_count++;
			if (dot_count > 1) {
				std::cout << "ERROR: Invalid value" << "\n";
				return false;
			}
		}
		else if (!std::isdigit((unsigned char)(c))) {
			// If it's not a digit and not a dot, it's invalid
			std::cout << "ERROR: Invalid value" << "\n";
			return false;
		}
	}

	return true;
}

/**
 * @brief Extracts a JSON object from an HTTP response.
 *
 * Parses the body of the response and checks if it is valid JSON.
 *
 * @param resp The HTTP response to parse.
 * @param success Reference to a boolean indicating success or failure.
 * @return Parsed JSON object or an empty object on failure.
 */
static nlohmann::json extract_json_response(HttpResponse &resp, bool &success)
{
	// Extract the body from the response
	char *body = basic_extract_json_response(resp.raw);
	DIE(!body, "basic_extract_json_response");

	// Verify if the body is a valid JSON
	if (!body || !nlohmann::json::accept(body)) {
		success = false;
		return nlohmann::json();
	}

	// Parse the JSON body
	success = true;
	return nlohmann::json::parse(body);
}

/**
 * @brief Authenticate admin and store session cookie.
 *
 * 1) Prompt for username and password  
 * 2) Build JSON payload and POST to /login  
 * 3) Send request, parse response status  
 * 4) On success extract “Set-Cookie” and save to cookies.admin  
 *
 * @param sockfd Connected socket descriptor.  
 * @param cookies Reference to Cookies struct to store admin cookies.
 */
void login_admin(int sockfd, Cookies &cookies)
{
	auto fields = read_fields({"username", "password"});
	const auto &username = fields[0];
	const auto &passwd = fields[1];

	if (passwd.empty() || passwd.find(" ") != std ::string ::npos || 
		username.empty() || username.find(" ") != std ::string ::npos) {
		std ::cout << "ERROR: Invalid username or password" << "\n";
		return;
	}

	// Build JSON payload
	nlohmann::json json_to_send;
	json_to_send["username"] = username;
	json_to_send["password"] = passwd;
	std::string payload = json_to_send.dump();
	char *payload_body = strdup(payload.c_str());
	DIE(!payload_body, "strdup");

	// Send POST request to /login
	char *request = compute_post_request(host, (char *)LOGIN, (char *)PAYLOAD_TYPE,
										 &payload_body, 1, cookies.admin, 
										 cookies.admin.size(), nullptr);
	DIE(!request, "compute_post_request");

	// Send request and receive response
	HttpResponse resp = send_request(sockfd, request);

	if (is_success(resp.status)) {
		std::cout << "SUCCESS: Admin logged in successfully" << "\n";

		// Extract cookies from the response
		char *cookie_buf[16];
		int cookie_count = 0;
		extract_cookie(resp.raw, cookie_buf, &cookie_count);
		for (int i = 0; i < cookie_count; ++i) {
			// Store cookies in the vector from Cookies struct
			cookies.admin.push_back(cookie_buf[i]);
		}
	} else {
		std::cout << "ERROR: Authentication failed" << "\n";
	}

	cleanup(request, resp.raw, payload_body);
}

/**
 * @brief Create a new user using POST.
 *
 * 1) Prompt for username and password  
 * 2) Build JSON payload and POST to /users  
 * 3) Print SUCCESS or ERROR based on HTTP status.
 *
 * @param sockfd Connected socket descriptor.  
 * @param cookies Admin cookies for authorization.
 */
void add_user(int sockfd, Cookies &cookies)
{
	auto fields = read_fields({"username", "password"});
	const auto &username = fields[0];
	const auto &passwd = fields[1];

	if (username.empty() || passwd.empty()) {
		std ::cout << "ERROR: Invalid username or password" << "\n";
		return;
	}

	// Build JSON payload
	nlohmann::json json_to_send;
	json_to_send["username"] = username;
	json_to_send["password"] = passwd;
	std::string payload = json_to_send.dump();
	char *payload_body = strdup(payload.c_str());
	DIE(!payload_body, "strdup");

	// Send POST request to /users
	char *request = compute_post_request(host, (char *)USERS, (char *)PAYLOAD_TYPE,
										 &payload_body, 1, cookies.admin, 
										 cookies.admin.size(), nullptr);
	DIE(!request, "compute_post_request");

	// Send request and receive response
	HttpResponse resp = send_request(sockfd, request);

	// Check the response status
	if (is_success(resp.status)) {
		std::cout << "SUCCESS: User added successfully\n";
	} else {
		std::cout << "ERROR: User addition failed" << "\n";
	}

	cleanup(request, resp.raw, payload_body);
}

/**
 * @brief Print a list of users from JSON.
 *
 * Iterates over JSON array or object["users"], and prints
 * each user's id, name, and password.
 *
 * @param resp_json Parsed JSON containing user list.
 */
void display_users(const nlohmann::json &resp_json)
{
	std::cout << "SUCCESS: User list" << "\n";
	const nlohmann::json *arr = nullptr;

	// First try the {"users": [...]} case
	if (resp_json.is_object()) {
		if (resp_json.contains("users")) {
			const auto &maybe_users = resp_json["users"];
			if (maybe_users.is_array()) {
				arr = &maybe_users;
			}
		}
	}

	// If that failed, fall back to the top‐level array
	if (arr == nullptr) {
		if (resp_json.is_array()) {
			arr = &resp_json;
		}
	}

	// If we have a valid array, print the users
	if (arr) {
		for (auto &user : *arr) {
			int id = user["id"].get<int>();
			auto name = user["username"].get<std::string>();
			auto pass = user["password"].get<std::string>();
			std::cout << "#" << id << " " << name << ":" << pass << "\n";
		}
	}
}

/**
 * @brief Retrieve and display all users.
 *
 * 1) GET /users with admin cookies  
 * 2) If the status is Succesfull(2xx) parse body JSON and call display_users()  
 * 3) Otherwise print error.
 *
 * @param sockfd Connected socket descriptor.  
 * @param cookies Admin cookies.
 */
void get_users(int sockfd, Cookies &cookies) {
	char *request = compute_get_request(host, (char *)USERS, nullptr, cookies.admin,
										(int)cookies.admin.size(), nullptr);
	DIE(!request, "compute_get_request");

	HttpResponse resp = send_request(sockfd, request);
	// Check the response status
	if (is_success(resp.status)) {
		char *body = basic_extract_json_response(resp.raw);
		DIE(!body, "basic_extract_json_response");

		if (body) {
			// Parse the JSON body
			auto json_response = nlohmann::json::parse(body);
			display_users(json_response);
		}
		else {
			std::cout << "SUCCESS: User list" << "\n";
		}
	} else {
		std::cout << "ERROR: Failed to fetch users" << "\n";
	}

	cleanup(request, resp.raw);
}

/**
 * @brief Logout admin and clear cookies.
 *
 * GET /logout with admin cookies. On success free
 * cookies.admin entries and clear container.
 *
 * @param sockfd Connected socket descriptor.  
 * @param cookies Admin cookies struct to clear.
 */
void logout_admin(int sockfd, Cookies &cookies)
{
	if (cookies.admin.empty()) {
		std::cout << "ERROR: Admin not authenticated" << "\n";
		return;
	}

	char *request = compute_get_request(host, (char *)LOGOUT, nullptr, cookies.admin, 
										(int)cookies.admin.size(), nullptr);
	DIE(!request, "compute_get_request");

	HttpResponse resp = send_request(sockfd, request);
	// Check the response status
	if (is_success(resp.status)) {
		std ::cout << "SUCCESS: Admin logged out" << "\n";
		for (auto &cookie : cookies.admin) {
			free(cookie);
		}
		cookies.admin.clear();
	} else {
		std ::cout << "ERROR: Logout failed" << "\n";
	}

	cleanup(request, resp.raw);
}

/**
 * @brief Delete a user by username.
 *
 * 1) Prompt for username  
 * 2) DELETE /users/{username} with admin cookies  
 * 3) Print SUCCESS or ERROR.
 *
 * @param sockfd Connected socket descriptor.  
 * @param cookies Admin cookies for auth.
 */
void delete_user(int sockfd, Cookies &cookies)
{
	auto fields = read_fields({"username"});
	const auto &username = fields[0];

	if (username.empty()) {
		std::cout << "ERROR: Invalid username\n";
		return;
	}

	// Build the URL for the DELETE request
	char url[LINELEN];
	snprintf(url, sizeof(url), "%s/%s", USERS, username.c_str());

	// Send DELETE request to /users/{username}
	char *request = compute_delete_request(host, url, cookies.admin, 
										   (int)cookies.admin.size(), nullptr);
	DIE(!request, "compute_delete_request");

	HttpResponse resp = send_request(sockfd, request);
	// Check the response status
	if (is_success(resp.status)) {
		std::cout << "SUCCESS: User deleted" << "\n";
	} else {
		std::cout << "ERROR: User deletion failed" << "\n";
	}

	cleanup(request, resp.raw);
}

/**
 * @brief Authenticate standard user and store cookies.
 *
 * 1) Prompt for admin_username, username and password  
 * 2) POST to /login_user with admin cookies  
 * 3) On success extract and store user cookies.
 *
 * @param sockfd Connected socket descriptor.  
 * @param cookies Cookies struct to append user cookies.
 */
void login(int sockfd, Cookies &cookies)
{

	auto fields = read_fields({"admin_username", "username", "password"});
	const auto &admin_username = fields[0];
	const auto &username = fields[1];
	const auto &passwd = fields[2];

	if (passwd.empty() || passwd.find(" ") != std ::string ::npos ||
		username.empty() || username.find(" ") != std ::string ::npos) {
			std ::cout << "ERROR: Invalid username or password" << "\n";
			return;
	}

	// Build JSON payload
	nlohmann::json json_to_send;
	json_to_send["admin_username"] = admin_username;
	json_to_send["username"] = username;
	json_to_send["password"] = passwd;
	std::string payload = json_to_send.dump();
	
	char *body = strdup(payload.c_str());
	DIE(!body, "strdup");

	// Send POST request to /login_user
	char *request = compute_post_request(host, (char *)LOGIN_USER, (char *)PAYLOAD_TYPE,
										 &body, 1, cookies.admin, cookies.admin.size(),
										 nullptr);
	DIE(!request, "compute_post_request");

	// Send request and receive response
	HttpResponse resp = send_request(sockfd, request);
	// Check the response status
	if (is_success(resp.status)) {
		std ::cout << "SUCCESS: User logged in successfully" << "\n";
		char *cookie[16];
		int cookie_count = 0;
		// Extract cookies from the response and store them in the cookies struct
		extract_cookie(resp.raw, cookie, &cookie_count);
		for (int i = 0; i < cookie_count; i++) {
			cookies.user.push_back(cookie[i]);
		}
	} else {
		std ::cout << "ERROR: Authentification failed" << "\n";
	}

	cleanup(request, resp.raw, body);
}

/**
 * @brief Request a JWT token for library access.
 *
 * GET /library/access with user cookies. On success status,
 * extract “token” field from JSON and assign to jwt_token.
 *
 * @param sockfd Connected socket descriptor.  
 * @param cookies User cookies.  
 * @param jwt_token Output string to receive JWT.
 */
void get_access(int sockfd, Cookies &cookies,
				std::string &jwt_token)
{
	// Build and send GET to /api/v1/tema/library/access
	char *request = compute_get_request(host, LIB_ACCESS, nullptr, cookies.user,
										(int)cookies.user.size(), nullptr);
	DIE(!request, "compute_get_request");

	// Send request and receive response
	HttpResponse resp = send_request(sockfd, request);
	// Check the response status
	if (is_success(resp.status)) {
		char *raw_token = extract_token(resp.raw);
		if (raw_token) {
			// Store the token in the output string
			jwt_token = raw_token;
			free(raw_token);
		}
		std::cout << "SUCCESS: JWT token received" << "\n";
	} else {
		std::cout << "ERROR: Authentication required" << "\n";
	}

	cleanup(request, resp.raw);
}

/**
 * @brief Add a new movie to catalog.
 *
 * 1) Prompt title, description, year, rating  
 * 2) Validate inputs, build JSON  
 * 3) POST to /movies with JWT and user cookies  
 * 4) Print SUCCESS or ERROR.
 *
 * @param sockfd Connected socket descriptor.  
 * @param cookies User cookies for auth.  
 * @param jwt_token JWT string for authorization.
 */
void add_movie(int sockfd, Cookies &cookies,
			const std::string &jwt_token)
{
	auto fields = read_fields({"title", "description", "year", "rating"});
	const auto &title = fields[0];
	const auto &description = fields[1];
	const auto &year_str = fields[2];
	const auto &rating_str = fields[3];

	// Validate inputs
	if (title.empty() || description.empty()) {
		std::cout << "ERROR: Invalid or incomplete data" << "\n";
		return;
	}

	// Validate year and rating
	if (!validate_numeric_id(year_str)) {
		std::cout << "ERROR: Invalid year" << "\n";
		return;
	}
	int year = std::stoi(year_str);

	if (!validate_decimal(rating_str)) {
		std::cout << "ERROR: Invalid rating" << "\n";
		return;
	}
	double rating = std::stod(rating_str);

	// Build JSON payload
	nlohmann::json json_to_send;
	json_to_send["title"] = title;
	json_to_send["year"] = year;
	json_to_send["description"] = description;
	json_to_send["rating"] = rating;
	std::string payload = json_to_send.dump();
	char *body = strdup(payload.c_str());
	DIE(!body, "strdup");

	// Send POST request to /movies
	char *request = compute_post_request(host, MOVIES, PAYLOAD_TYPE,&body, 1, 
										 cookies.user, (int)cookies.user.size(),
										 jwt_token.c_str());
	DIE(!request, "compute_post_request");
	// Send request and receive response
	HttpResponse resp = send_request(sockfd, request);
	if (is_success(resp.status)) {
		std::cout << "SUCCESS: Movie added" << "\n";
	} else {
		std::cout << "ERROR: Access denied or invalid data" << "\n";
	}

	cleanup(request, resp.raw, body);
}

/**
 * @brief Compare two movie JSON objects by id.
 *
 * Used to sort movie lists in ascending order by "id" field.
 *
 * @param a First movie JSON.  
 * @param b Second movie JSON.  
 * @return true if a.id < b.id.
 */
bool cmp(const nlohmann::json &a, const nlohmann::json &b)
{
	int id_a = a["id"].get<int>();
	int id_b = b["id"].get<int>();
	return id_a < id_b;
}

/**
 * @brief Display sorted movie list.
 *
 * 1) Extract JSON array or object["movies"]  
 * 2) Sort with cmp() and print each "#id title".
 *
 * @param data Parsed JSON containing movies.
 */
static void display_movies_list(const nlohmann::json &data)
{
	const nlohmann::json *arr = nullptr;
	if (data.is_array()) {
	// If the top-level JSON is an array, use it directly
		arr = &data;
	} else if (data.is_object() && data.contains("movies") &&
			data["movies"].is_array()) {
		//  If it's an object with a "movies" array, use that
		arr = &data["movies"];
	}

	// Sort the movies by id
	std::vector<nlohmann::json> movies;
	if (arr) {
		for (const auto &m : *arr) {
			movies.push_back(m);
		}
		std::sort(movies.begin(), movies.end(), cmp);
	}

	// Print the sorted movie list
	std::cout << "SUCCESS: Movie list" << "\n";
	for (const auto &m : movies) {
		int id = m["id"].get<int>();
		auto title = m["title"].get<std::string>();
		std::cout << "#" << id << " " << title << "\n";
	}
}

/**
 * @brief Retrieve and show all movies.
 *
 * GET /movies with JWT and user cookies. On success status,
 * parse JSON with extract_json_response() and call
 * display_movies_list(). Otherwise print error.
 *
 * @param sockfd Connected socket descriptor.  
 * @param cookies User cookies.  
 * @param jwt_token JWT for authorization.
 */
void get_movies(int sockfd, Cookies &cookies, const std::string &jwt_token)
{
	// Compute GET request to /movies
	char *request = compute_get_request(host, MOVIES, nullptr,cookies.user,
										(int)cookies.user.size(),jwt_token.c_str());
	DIE(!request, "compute_get_request");

	// Send request and receive response
	HttpResponse resp = send_request(sockfd, request);
	// Check the response status
	if (!is_success(resp.status)) {
		std::cout << "ERROR: Access denied" << "\n";
		cleanup(request, resp.raw);
		return;
	}

	// Extract JSON response
	bool json_success = false;
	auto json_data = extract_json_response(resp, json_success);
	if (!json_success) {
		std::cout << "ERROR: Invalid server response" << "\n";
		cleanup(request, resp.raw);
		return;
	}

	// Display the movie list
	display_movies_list(json_data);

	cleanup(request, resp.raw);
}

/**
 * @brief Get details of one movie by id.
 *
 * 1) Prompt for id  
 * 2) Validate numeric  
 * 3) GET /movies/{id} with JWT & cookies  
 * 4) On success status, print raw JSON body, else print error.
 *
 * @param sockfd Connected socket descriptor.  
 * @param cookies User cookies.  
 * @param jwt_token JWT for authorization.
 */
void get_movie(int sockfd, Cookies &cookies,
			   const std::string &jwt_token)
{
	auto fields = read_fields({"id"});
	const auto &id = fields[0];

	if (!validate_numeric_id(id)) {
		std::cout << "ERROR: Invalid ID" << "\n";
		return;
	}

	// Build path
	std::string path = std::string(MOVIES) + "/" + id;

	// send GET with cookies + JWT
	char *request = compute_get_request(host, path.c_str(), nullptr, cookies.user,
										(int)cookies.user.size(), jwt_token.c_str());
	DIE(!request, "compute_get_request");
	
	HttpResponse resp = send_request(sockfd, request);
	// Check the response status
	if (is_success(resp.status)) {
		char *body = basic_extract_json_response(resp.raw);
		DIE(!body, "basic_extract_json_response");
		// Print the JSON body
		if (body) {
			std::cout << body << "\n";
		} else {
			std::cout << "ERROR: Invalid response" << "\n";
		}
	} else if (resp.status == NOT_FOUND) {
		std::cout << "ERROR: Invalid movie ID" << "\n";
	} else {
		std::cout << "ERROR: Access denied" << "\n";
	}

	cleanup(request, resp.raw);
}

/**
 * @brief Delete a movie by id.
 *
 * 1) Prompt for id  
 * 2) DELETE /movies/{id} with JWT & cookies  
 * 3) Print SUCCESS or ERROR.
 *
 * @param sockfd Connected socket descriptor.  
 * @param cookies User cookies.  
 * @param jwt_token JWT for authorization.
 */
void delete_movie(int sockfd, Cookies &cookies,
				  const std::string &jwt_token)
{

	auto fields = read_fields({"id"});
	const auto &id = fields[0];

	if (id.empty()) {
		std ::cout << "ERROR: Invalid ID\n";
		return;
	}

	std::string path = std::string(MOVIES) + "/" + id;

	// send DELETE with cookies + JWT
	char *request = compute_delete_request(host, (char *)path.c_str(), cookies.user, (int)cookies.user.size(), jwt_token.c_str());
	DIE(!request, "compute_delete_request");

	HttpResponse resp = send_request(sockfd, request);
	// Check the response status
	if (is_success(resp.status)) {
		std ::cout << "SUCCESS: Movie deleted" << "\n";
	} else {
		std ::cout << "ERROR: Movie deletion failed" << "\n";
	}

	cleanup(request, resp.raw);
}

/**
 * @brief Logout user and clear cookies.
 *
 * GET /logout_user with user cookies. On success
 * free cookies.user entries and clear container.
 *
 * @param sockfd Connected socket descriptor.  
 * @param cookies User cookies struct to clear.
 */
void logout(int sockfd, Cookies &cookies)
{
	if (cookies.user.empty()) {
		std::cout << "ERROR: User not authenticated" << "\n";
		return;
	}

	// Send GET request to /logout_user
	char *request = compute_get_request(host,(char *)LOGOUT_USER, nullptr, cookies.user,
										(int)cookies.user.size(), nullptr);
	DIE(!request, "compute_get_request");
	HttpResponse resp = send_request(sockfd, request);

	// Check the response status
	if (is_success(resp.status)) {
		std::cout << "SUCCESS: User logged out" << "\n";
		// Free cookies
		for (auto c : cookies.user) {
			free(c);
		}
		cookies.user.clear();
	} else {
		std::cout << "ERROR: Logout failed" << "\n";
	}

	cleanup(request, resp.raw);
}

/**
 * @brief Update movie details by id.
 *
 * 1) Prompt id, title, year, description, rating  
 * 2) Validate inputs, build JSON  
 * 3) PUT /movies/{id} with JWT & cookies  
 * 4) Print SUCCESS or ERROR.
 *
 * @param sockfd Connected socket descriptor.  
 * @param cookies User cookies.  
 * @param jwt_token JWT for authorization.
 */
void update_movie(int sockfd, Cookies &cookies,
				  const std::string &jwt_token)
{
	auto fields = read_fields({"id", "title", "year", "description", "rating"});
	const auto &id = fields[0];
	const auto &new_title = fields[1];
	const auto &new_year_s = fields[2];
	const auto &new_description = fields[3];
	const auto &new_rating_s = fields[4];

	// Validate inputs
	if (id.empty() || new_title.empty() || new_year_s.empty() ||
		new_description.empty() || new_rating_s.empty()) {
		std::cout << "ERROR: Invalid input" << "\n";
		return;
	}
	
	// Check if id is numeric
	if (!std::all_of(id.begin(), id.end(), ::isdigit)){
		std::cout << "ERROR: Invalid movie ID" << "\n";
		return;
	}

	// Validate year and rating
	if (!std::all_of(new_year_s.begin(), new_year_s.end(), ::isdigit)) {
		std::cout << "ERROR: Invalid input" << "\n";
		return;
	}
	int new_year = std::stoi(new_year_s);

	if (!validate_decimal(new_rating_s)) {
		std::cout << "ERROR: Invalid input" << "\n";
		return;
	}
	double new_rating = std::stod(new_rating_s);

	// Build JSON payload
	nlohmann::json json_to_send;
	json_to_send["title"] = new_title;
	json_to_send["year"] = new_year;
	json_to_send["description"] = new_description;
	json_to_send["rating"] = new_rating;
	std::string payload = json_to_send.dump();
	char *body_data = strdup(payload.c_str());
	DIE(!body_data, "strdup");

	// Build the path for the PUT request
	std::string path = std::string(MOVIES) + "/" + id;
	char *request = compute_put_request(host, (char *)path.c_str(), (char *)PAYLOAD_TYPE,
										body_data, cookies.user,(int)cookies.user.size(),
										jwt_token.c_str());
	DIE(!request, "compute_put_request");
	HttpResponse resp = send_request(sockfd, request);

	if (is_success(resp.status)) {
		std::cout << "SUCCESS: Movie updated" << "\n";
	} else {
		std::cout << "ERROR: Movie update failed" << "\n";
	}

	cleanup(request, resp.raw, body_data);
	close_connection(sockfd);
}

/**
 * @brief Display a list of collections.
 *
 * Iterate array or object["collections"], printing
 * each "#id: title".
 *
 * @param data Parsed JSON with collections.
 */
static void display_collections_list(const nlohmann::json &data)
{
	const nlohmann::json *arr = nullptr;
	if (data.is_array()) {
		// If the top-level JSON is an array, use it directly
		arr = &data;
	}
	else if (data.is_object() &&
			 data.contains("collections") &&
			 data["collections"].is_array()) {
	// If it's an object with a "collections" array, use that
		arr = &data["collections"];
	}

	std::cout << "SUCCESS: Collection list" << "\n";
	if (arr) {
		for (const auto &c : *arr) {
			int id = c["id"].get<int>();
			auto title = c["title"].get<std::string>();
			std::cout << "#" << id << ": " << title << "\n";
		}
	}
}

/**
 * @brief Retrieve and display all collections.
 *
 * Sends a GET to the collections endpoint with JWT and user cookies.
 * Parses the JSON response and calls display_collections_list(), or
 * prints an error if access is denied or response is invalid.
 *
 * @param sockfd     Connected socket descriptor.
 * @param cookies    Struct holding user cookies.
 * @param jwt_token  JWT string for authorization.
 */
void get_collections(int sockfd, Cookies &cookies,
					 const std::string &jwt_token)
{
	// build GET request to /collections
	char *request = compute_get_request(host, COLLECTIONS, nullptr, cookies.user,
										(int)cookies.user.size(), jwt_token.c_str());
	DIE(!request, "compute_get_request");

	// Send request and receive response
	HttpResponse resp = send_request(sockfd, request);
	if (!is_success(resp.status)) {
		std::cout << "ERROR: Access denied" << "\n";
		cleanup(request, resp.raw);
		return;
	}

	// Parse JSON response
	bool json_success = false;
	auto json_data = extract_json_response(resp, json_success);
	if (!json_success) {
		std::cout << "ERROR: Invalid response" << "\n";
		cleanup(request, resp.raw);
		return;
	}

	// Display the collections list
	display_collections_list(json_data);

	cleanup(request, resp.raw);
}

/**
 * @brief Check if a movie exists by id.
 *
 * Opens a new connection, sends a GET to /movies/{mid} with JWT and
 * cookies, and returns true if the response status indicates success.
 *
 * @param mid       Movie ID to check.
 * @param cookies   Struct holding user cookies.
 * @param jwt       JWT string for authorization.
 * @return true if the movie exists, false otherwise.
 */
static bool movie_exists(int mid,
						 const Cookies &cookies,
						 const std::string &jwt)
{
	// Build the path for the GET request
	std::string path = std::string(MOVIES) + "/" + std::to_string(mid);
	int sockfd = open_connection(host, port, AF_INET, SOCK_STREAM, 0);
	DIE(sockfd < 0, "open_connection");

	// Send GET request to /movies/{mid}
	char *req = compute_get_request(host, path.c_str(), nullptr, cookies.user,
									(int)cookies.user.size(), jwt.c_str());
	DIE(!req, "compute_get_request");
	
	// Send request and receive response
	HttpResponse resp = send_request(sockfd, req);
	cleanup(req, resp.raw);
	return is_success(resp.status);
}

/**
 * @brief Create a new collection on the server.
 *
 * Builds a JSON body with the collection title and sends a POST to
 * /collections with JWT and user cookies. Parses and returns the new
 * collection’s id, or -1 on failure.
 *
 * @param title    Title of the new collection.
 * @param cookies  Struct holding user cookies.
 * @param jwt      JWT string for authorization.
 * @return New collection ID, or -1 if creation failed.
 */
static int create_collection(const std::string &title,
							 const Cookies &cookies,
							 const std::string &jwt)
{
	// Build JSON payload
	nlohmann::json json_to_send;
	json_to_send["title"] = title;
	std::string payload = json_to_send.dump();
	char *body = strdup(payload.c_str());
	DIE(!body, "strdup");

	// Build POST request to /collections
	char *req = compute_post_request(host, (char *)COLLECTIONS, (char *)PAYLOAD_TYPE,
									 &body, 1, cookies.user, (int)cookies.user.size(),
									 jwt.c_str());
	DIE(!req, "compute_post_request");

	// Open connection and send request
	int sockfd = open_connection(host, port, AF_INET, SOCK_STREAM, 0);
	DIE(sockfd < 0, "open_connection");
	
	HttpResponse resp = send_request(sockfd, req);
	// Check the response status
	if (!is_success(resp.status)) {
		std::cout << "ERROR: Access denied or invalid data" << "\n";
		cleanup(req, resp.raw, body);
		return -1;
	}

	// extract JSON response
	char *json_part = basic_extract_json_response(resp.raw);
	DIE(!json_part, "basic_extract_json_response");
	auto json_resp = nlohmann::json::parse(json_part);
	int cid = json_resp.value("id", -1);

	cleanup(req, resp.raw, body);
	return cid;
}

/**
 * @brief Add a movie to an existing collection.
 *
 * Builds a JSON body with the movie id and sends a POST to
 * /collections/{coll_id}/movies with JWT and user cookies.
 *
 * @param coll_id  ID of the target collection.
 * @param mid      Movie ID to add.
 * @param cookies  Struct holding user cookies.
 * @param jwt      JWT string for authorization.
 */
static void add_one_movie_to_collection(int coll_id, int mid,
										const Cookies &cookies,
										const std::string &jwt)
{
	nlohmann::json json_to_send;
	json_to_send["id"] = mid;
	std::string payload = json_to_send.dump();
	char *body = strdup(payload.c_str());
	DIE(!body, "strdup");

	// Build POST request to /collections/{coll_id}/movies
	std::string path = std::string(COLLECTIONS) + "/" + std::to_string(coll_id) + "/movies";
	char *req = compute_post_request(host, path.c_str(), (char *)PAYLOAD_TYPE,
									 &body, 1, cookies.user, (int)cookies.user.size(),
									 jwt.c_str());
	DIE(!req, "compute_post_request");

	// Open connection and send request
	int sockfd = open_connection(host, port, AF_INET, SOCK_STREAM, 0);
	DIE(sockfd < 0, "open_connection");

	HttpResponse resp = send_request(sockfd, req);

	cleanup(req, resp.raw, body);
}

/**
 * @brief Create a collection and populate it with movies.
 *
 * Reads the collection title and a set of movie ids, validates each
 * id exists, creates the collection, and adds each movie. Prints a
 * final success or error message.
 *
 * @param sockfd     Connected socket descriptor.
 * @param cookies    Struct holding user cookies.
 * @param jwt_token  JWT string for authorization.
 */
void add_collection(int sockfd, Cookies &cookies,
					const std::string &jwt_token)
{
	auto fields = read_fields({"title", "num_movies"});
	const auto &title = fields[0];
	const auto &num_s = fields[1];

	// Validate inputs
	if (title.empty() || num_s.empty() ||
		!std::all_of(num_s.begin(), num_s.end(), ::isdigit)) {
		std::cout << "ERROR: Invalid or incomplete data" << "\n";
		return;
	}

	int num = std::stoi(num_s);
	
	// use unordered_set to avoid duplicates
	std::unordered_set<int> mids;
	mids.reserve(num);
	for (int i = 0; i < num; ++i) {
		std::cout << "movie_id[" << i << "]=";
		std::string s;
		std::getline(std::cin, s);
		// Validate each movie id
		if (s.empty() || !std::all_of(s.begin(), s.end(), ::isdigit)) {
			std::cout << "ERROR: Invalid or incomplete data" << "\n";
			return;
		}
		// Insert into the set
		mids.insert(std::stoi(s));
	}

	// Check if all movie ids exist
	for (int mid : mids) {
		if (!movie_exists(mid, cookies, jwt_token)) {
			std::cout << "ERROR: Invalid or incomplete data" << "\n";
			return;
		}
	}

	// Create the collection
	int coll_id = create_collection(title, cookies, jwt_token);
	if (coll_id < 0) {
		std::cout << "ERROR: Access denied or invalid data" << "\n";
		return;
	}

	// Add each movie to the collection
	for (int mid : mids)
		add_one_movie_to_collection(coll_id, mid, cookies, jwt_token);

	std::cout << "SUCCESS: Collection added" << "\n";
}

/**
 * @brief Display detailed information for one collection.
 *
 * Validates the JSON has “title”, “owner” and a “movies” array, then
 * prints the collection’s title, owner and each movie’s id and title.
 *
 * @param data Parsed JSON object for a single collection.
 * @return true if the data was valid and printed; false otherwise.
 */
static bool display_collection_details(const nlohmann::json &data)
{
	// Check if the JSON is an object and contains the required fields
	if (!data.is_object() ||
		!data.contains("title") || !data["title"].is_string() ||
		!data.contains("owner") || !data["owner"].is_string() ||
		!data.contains("movies") || !data["movies"].is_array()) {
		
		std::cout << "ERROR: Invalid collection data" << "\n";
		return false;
	}

	// Print collection details
	std::cout << "SUCCESS: Detalii colecție\n";
	std::cout << "title: " << data["title"].get<std::string>() << "\n";
	std::cout << "owner: " << data["owner"].get<std::string>() << "\n";

	for (const auto &m : data["movies"]) {
		if (m.is_object() &&
			m.contains("id") && m["id"].is_number_integer() &&
			m.contains("title") && m["title"].is_string()) {
			// Print movie details
			std::cout << "#" << m["id"].get<int>()
					<< ": " << m["title"].get<std::string>() 
					<< "\n";
		}
	}
	return true;
}

/**
 * @brief Retrieve and show one collection by id.
 *
 * Prompts for a collection id, sends a GET to
 * /collections/{id} with JWT and cookies, and on success parses the
 * JSON and calls display_collection_details(). Prints errors otherwise.
 *
 * @param sockfd     Connected socket descriptor.
 * @param cookies    Struct holding user cookies.
 * @param jwt_token  JWT string for authorization.
 */
void get_collection(int sockfd, Cookies &cookies,
					const std::string &jwt_token)
{
	auto fields = read_fields({"id"});
	const auto &id = fields[0];

	// Validate the collection id
	if (id.empty() || !std::all_of(id.begin(), id.end(), ::isdigit)) {
		std::cout << "ERROR: Invalid ID" << "\n";
		return;
	}

	// Build the path for the GET request
	std::string path = std::string(COLLECTIONS) + "/" + id;
	char *request = compute_get_request(host, (char *)path.c_str(), nullptr,
										cookies.user, (int)cookies.user.size(),
										jwt_token.c_str());
	DIE(!request, "compute_get_request");
	HttpResponse resp = send_request(sockfd, request);

	// Check the response status
	if (is_success(resp.status)) {
		bool json_success = false;
		auto json_data = extract_json_response(resp, json_success);
	
		if (!json_success || !display_collection_details(json_data)) {
			std::cout << "ERROR: Invalid response" << "\n";
		}
	} else if (resp.status == NOT_FOUND) {
		std::cout << "ERROR: Invalid ID" << "\n";
	} else {
		std::cout << "ERROR: Access denied" << "\n";
	}

	cleanup(request, resp.raw);
}

/**
 * @brief Print a standardized status message based on HTTP code.
 *
 * If the code indicates success, prints the provided success_msg.
 * Otherwise maps common error codes to human‐readable messages.
 * 
 * Resource: https://umbraco.com/knowledge-base/http-status-codes/
 *
 * @param code         HTTP status code.
 * @param success_msg  Message to print on success codes .
 */
static void print_status(int code, const char *success_msg)
{
	if (is_success(code)) {
		std::cout << success_msg << "\n";
		return;
	}
	switch (code) {
	case BAD_REQUEST:
		std::cout << "ERROR: Invalid or incomplete data" << "\n";
		break;
	case NOT_FOUND:
		std::cout << "ERROR: Invalid ID" << "\n";
		break;
	case FORBIDDEN:
		std::cout << "ERROR: You are not the owner" << "\n";
		break;
	default:
		std::cout << "ERROR: Access denied" << "\n";
		break;
	}
}

/**
 * @brief Delete a collection by id.
 *
 * Reads a collection id, sends a DELETE to
 * /collections/{id} with JWT and user cookies, then calls
 * print_status() to display the result.
 *
 * @param sockfd     Connected socket descriptor.
 * @param cookies    Struct holding user cookies.
 * @param jwt_token  JWT string for authorization.
 */
void delete_collection(int sockfd, Cookies &cookies,
					   const std::string &jwt_token)
{
	auto fields = read_fields({"id"});
	const auto &id = fields[0];

	if (!validate_numeric_id(id)) {
		std::cout << "ERROR: Invalid ID" << "\n";
		return;
	}

	// Build the path and send the DELETE request
	std::string path = std::string(COLLECTIONS) + "/" + id;
	char *request = compute_delete_request(host, path.c_str(), cookies.user,
										   (int)cookies.user.size(), jwt_token.c_str());
	DIE(!request, "compute_delete_request");

	HttpResponse resp = send_request(sockfd, request);

	// Interpret the response status
	print_status(resp.status, "SUCCESS: Collection deleted");

	cleanup(request, resp.raw);
}

/**
 * @brief Add a movie to a collection via user input.
 *
 * Prompts for collection_id and movie_id, validates them, sends a
 * POST to /collections/{collection_id}/movies with JWT and cookies,
 * and prints the status result.
 *
 * @param sockfd     Connected socket descriptor.
 * @param cookies    Struct holding user cookies.
 * @param jwt_token  JWT string for authorization.
 */
void add_movie_to_collection(int sockfd, Cookies &cookies,
							 const std::string &jwt_token)
{
	auto fields = read_fields({"collection_id", "movie_id"});
	const auto &coll_s = fields[0];
	const auto &movie_s = fields[1];

	// Check if collection_id and movie_id are valid
	if (coll_s.empty() || movie_s.empty() || !std::all_of(coll_s.begin(), coll_s.end(), ::isdigit)
		|| !std::all_of(movie_s.begin(), movie_s.end(), ::isdigit)) {
		std::cout << "ERROR: Invalid or incomplete data" << "\n";
		return;
	}
	// Convert to integers
	int coll_id = std::stoi(coll_s);
	int movie_id = std::stoi(movie_s);

	// Construct the JSON payload
	nlohmann::json json_to_send;
	json_to_send["id"] = movie_id;
	std::string payload = json_to_send.dump();
	char *body = strdup(payload.c_str());
	DIE(!body, "strdup");

	// Build the path for the POST request
	std::string path = std::string(COLLECTIONS) + "/" + std::to_string(coll_id) + "/movies";
	char *request = compute_post_request(host, (char *)path.c_str(), (char *)PAYLOAD_TYPE,
										 &body, 1, cookies.user, (int)cookies.user.size(),
										 jwt_token.c_str());
	DIE(!request, "compute_post_request");
	
	HttpResponse resp = send_request(sockfd, request);
	// Check the response status
	print_status(resp.status, "SUCCESS: Movie added to collection");
	cleanup(request, resp.raw);
}

/**
 * @brief Remove a movie from a collection.
 *
 * Prompts for collection_id and movie_id, validates inputs, sends a
 * DELETE to /collections/{collection_id}/movies/{movie_id} with
 * JWT and cookies, and prints the status result.
 *
 * @param sockfd     Connected socket descriptor.
 * @param cookies    Struct holding user cookies.
 * @param jwt_token  JWT string for authorization.
 */
void delete_movie_from_collection(int sockfd, Cookies &cookies,
								  const std::string &jwt_token)
{
	auto fields = read_fields({"collection_id", "movie_id"});
	const auto &coll_s = fields[0];
	const auto &movie_s = fields[1];

	// Validate inputs
	if (coll_s.empty() || movie_s.empty() ||
		!std::all_of(coll_s.begin(), coll_s.end(), ::isdigit) ||
		!std::all_of(movie_s.begin(), movie_s.end(), ::isdigit)) {
		std::cout << "ERROR: Invalid or incomplete data" << "\n";
		return;
	}
	// Convert to integers
	int coll_id = std::stoi(coll_s);
	int movie_id = std::stoi(movie_s);

	// Build the path for the DELETE request
	std::string path = std::string(COLLECTIONS) + "/" +
					std::to_string(coll_id) + "/movies/" +
					std::to_string(movie_id);

	// Send DELETE request with JWT and cookies
	char *request = compute_delete_request(host, path.c_str(), cookies.user,
										   (int)cookies.user.size(), jwt_token.c_str());
	DIE(!request, "compute_delete_request");

	HttpResponse resp = send_request(sockfd, request);
	// Check the response status
	print_status(resp.status, "SUCCESS: Movie removed from collection");

	cleanup(request, resp.raw);
}

/**
 * @brief Main command‐loop and dispatcher.
 *
 * Opens a connection, reads a command line from stdin, parses it
 * into a CommandType, invokes the corresponding handler, and loops
 * until the exit command is received.
 *
 * @return 0 on normal exit.
 */
int main()
{
	Cookies cookies; // Struct for user and admin cookies
	std::string jwt_token; // JWT token for authorization
	std::string line; // Input line buffer

	while (1) {
		// Open connection
		int sockfd = open_connection(host, port, AF_INET, SOCK_STREAM, 0);
		DIE(sockfd < 0, "open_connection");
		// Read user command
		std::getline(std::cin, line);
		CommandType cmd = parse_command(line);

		// Dispatch
		switch (cmd) {
		case CMD_LOGIN_ADMIN:
			login_admin(sockfd, cookies);
			break;
		case CMD_ADD_USER:
			add_user(sockfd, cookies);
			break;
		case CMD_GET_USERS:
			get_users(sockfd, cookies);
			break;
		case CMD_DELETE_USER:
			delete_user(sockfd, cookies);
			break;
		case CMD_LOGOUT_ADMIN:
			logout_admin(sockfd, cookies);
			break;
		case CMD_LOGIN:
			login(sockfd, cookies);
			break;
		case CMD_GET_ACCESS:
			get_access(sockfd, cookies, jwt_token);
			break;
		case CMD_ADD_MOVIE:
			add_movie(sockfd, cookies, jwt_token);
			break;
		case CMD_GET_MOVIES:
			get_movies(sockfd, cookies, jwt_token);
			break;
		case CMD_GET_MOVIE:
			get_movie(sockfd, cookies, jwt_token);
			break;
		case CMD_DELETE_MOVIE:
			delete_movie(sockfd, cookies, jwt_token);
			break;
		case CMD_LOGOUT:
			logout(sockfd, cookies);
			break;
		case CMD_UPDATE_MOVIE:
			update_movie(sockfd, cookies, jwt_token);
			break;
		case CMD_GET_COLLECTIONS:
			get_collections(sockfd, cookies, jwt_token);
			break;
		case CMD_ADD_COLLECTION:
			add_collection(sockfd, cookies, jwt_token);
			break;
		case CMD_GET_COLLECTION:
			get_collection(sockfd, cookies, jwt_token);
			break;
		case CMD_DELETE_COLLECTION:
			delete_collection(sockfd, cookies, jwt_token);
			break;
		case CMD_ADD_MOVIE_TO_COLLECTION:
			add_movie_to_collection(sockfd, cookies, jwt_token);
			break;
		case CMD_DELETE_MOVIE_FROM_COLLECTION:
			delete_movie_from_collection(sockfd, cookies, jwt_token);
			break;
		case CMD_EXIT:
			close_connection(sockfd);
			return 0;
		case CMD_INVALID:
		default:
			std::cout << "Invalid command" << "\n";
		}
		close_connection(sockfd);
	}

	return 0;
}
