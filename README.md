Copyright © 2024-2025 Căruntu Dana-Maria 321CAa

# Web Client - Rest API Communication

This is a command-line HTTP client implementing admin and user workflows for a movie and collections server.
For using json features in C++, this project uses the lib nlohmann
[#include "json.hpp"](https://github.com/nlohmann/json/blob/develop/include/nlohmann/json.hpp)

> **Note:**
>
> - This project used 2 sleep days in the making of it.
> - Most of this project includes code from 
> [laboratory 9: HTTP](https://pcom.pages.upb.ro/labs/lab9/http.html)
> made by Protocols of Communications team, because
> it is based on HTTP requests to the server and parsing
> responses for error checking.

---

## Features & Flow

1. **Interactive command loop**  
   The client reads textual commands (`login_admin`, `add_user`, `get_movies`, etc.)
in a loop. Each command:
   - Opens a new TCP connection to the server.
   - Builds an HTTP request (GET/POST/PUT/DELETE).
   - Sends it, receives the full response.
   - Parses the status code and JSON body (when needed).
   - Prints `SUCCESS:` or `ERROR:` messages to stdout.
   - Closes the socket.

2. **Admin operations**  
   - `login_admin`: authenticate as administrator, store session cookies.  
   - `add_user` / `get_users` / `delete_user` / `logout_admin`: manage user accounts.

3. **User operations**  
   - `login`: for user login, stores user cookies.  
   - `get_access`: retrieves a JWT token for library operations.  
   - `add_movie` / `get_movies` / `get_movie` / `update_movie` / `delete_movie`: manage movies.  
   - `get_collections` / `add_collection` / `get_collection` / `delete_collection` /  
     `add_movie_to_collection` / `delete_movie_from_collection`: manage movie collections.  
   - `logout`: end user session, clear cookies.

---

## File Structure

- **buffer.hpp / buffer.cpp**
  Implements a dynamic `buffer` struct to accumulate socket reads, find substrings 
(headers, terminators), and manage memory.
  > Resources used :
  >[here](https://gitlab.cs.pub.ro/pcom/pcom-laboratoare-public/-/blob/master/lab9/buffer.c?ref_type=heads)

- **helpers.hpp / helpers.cpp**  
  - Socket helpers: `open_connection()`, `close_connection()`, `send_to_server()`,
`receive_from_server()`.  
  - HTTP header assembly: `compute_message()`.  
  - Response parsing: `basic_extract_json_response()`, `is_success()`, `parse_command()`.
  > Resources used for the function `is_succes` 
[here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status#successful_responses)

- **requests.hpp / requests.cpp**  
  Builders for raw HTTP requests:  
  - `compute_get_request()`  
  - `compute_post_request()`  
  - `compute_delete_request()`  
  - `compute_put_request()`  
  Each assembles the request line, standard headers 
(`Host`, `Content-Type`, `Content-Length`, `Cookie`, `Authorization: Bearer`),
terminates with `\r\n`, and appends the body if needed.

  > Resources used: 
  [here](https://gitlab.cs.pub.ro/pcom/pcom-laboratoare-public/-/blob/master/lab9/requests.c?ref_type=heads)

- **client.cpp**  
  - `send_request()`: wraps send/receive, parses status code.  
  - Command handlers: one function per command (ex: `login_admin()`, `add_movie()`, etc)
  - Input handling: `read_fields()`, validation (`validate_numeric_id()`, `validate_decimal()`).  
  - Memory cleanup: `cleanup()`
  - `main()`: loops reading commands, dispatches to handlers, and exits on `exit`.

---

## Key Data Structures

- **struct Cookies**  
  Holds two `std::vector<char*>`: one for admin cookies, one for user cookies.  
  Cookies are stored as null-terminated C-strings extracted from `Set-Cookie` headers.

- **struct HttpResponse**  
  Contains the raw response buffer (`char *`) and parsed HTTP status code (`int`).

- **enum CommandType**  
  Maps text commands to internal identifiers (ex: `CMD_LOGIN_ADMIN`, `CMD_ADD_MOVIE`, etc).

- **nlohmann::json**  
  Used to build request bodies and parse JSON responses.

---

## Project Structure

- `client.cpp`  
  Main entry point, interactive loop and handlers for each command.
- `helpers.cpp` / `helpers.hpp`  
  Basic socket API wrappers, HTTP buffer parsing, helpers.
- `requests.cpp` / `requests.hpp`  
  Builders for raw HTTP messages: `compute_get_request`, `compute_post_request`,
  `compute_delete_request`, `compute_put_request`. 
- `buffer.cpp` / `buffer.hpp`  
  Internal dynamic buffer for assembling and parsing responses.

---

## Implementation Details (client.cpp)

`client.cpp` drives the entire user experience.
The core logic is :

1. **Command‐per‐Function**  
   - Each command (ex: `login_admin`, `add_movie`, `get_collections`) lives in its own function.  

    It encapsulates input prompts, JSON payload building, HTTP dispatch and output in one place,
    simplifying maintenance.

2. **Interactive Loop**  
   In `main()` the client:  
   - Opens a fresh TCP connection for each command (`open_connection`).  
   - Reads the user’s command line and maps it to a `CommandType`.  
   - Calls the corresponding handler, passing in the socket, the cookies struct and the JWT token.  
   - Closes the socket before the next iteration.  
 
    By doing this , each command is independent, so we don’t keep connections open
    which makes error handling much easier.

3. **Session State**  
   - `struct Cookies` holds two vectors for storing cookies for each type of session (admin/user).
   - After a successful login, `extract_cookie()` parses the `Set-Cookie` header and stores it.  
   - `get_access()` retrieves a JWT and stores it in a `std::string`.  
   
   It holds cookies and the token so you can add the right headers easily.

4. **Unified Request/Response**  
   - `send_request()` wraps:  
     1. `send_to_server()`  
     2. `receive_from_server()` into a dynamic buffer  
     3. `close_connection()`  
     4. HTTP status code parsing via `sscanf`.  
   - Handlers then call `basic_extract_json_response()` or custom extractors (`extract_token`) as needed.  
  
  Centralizes all socket I/O and status‐code parsing, reducing repetitive code in each command.

5. **Early Input Validation**  
   - IDs and years use `std::all_of(..., ::isdigit)`.  
   - Ratings use `validate_decimal()` (non-empty, only digits and number of dots less than 1). 
   - Commands abort before any network call on invalid input.  
  
  Provides instant feedback, and keeps server load minimal.

6. **JSON via nlohmann::json**  
   - Request bodies for movies and collections are built with a small `json` object and `dump()`.  
   - Response bodies are parsed with `json::parse()`.  
  
  Guarantees correct quoting/escaping and makes payload construction concise.

7. **Memory Management**  
   - Every `compute_*_request()` and `strdup()` allocation is freed in `cleanup()`.  
   - Cookie allocations are freed on logout.  
  
  Prevents leaks in a long-running session.

  By organizing around per-command handlers, a shared I/O wrapper, explicit session state and
  early validation, `client.cpp` remains clear, extensible and robust against both user
  mistakes and network errors.

---

## Overall Command Summary

Below is step-by-step of what each command in `client.cpp` does:

- **login_admin**  
  - Prompt for `username` and `password`  
  - Validate that both are non-empty and contain no whitespace
  - Build JSON `{ "username":…, "password":… }`  
  - POST to `/login` with no token  
  - If 2xx(success message): extract cookies to `cookies.admin[]`  
  - Print success or error message

- **add_user**  
  - Prompt for `username` and `password`  
  - Validate that both fields are non-empty (so we don’t send an empty username or 
  password which the server would reject) 
  - Build JSON and POST to `/users` with admin cookies  
  - Print success or error message

- **get_users**  
  - GET `/users` with admin cookies  
  - If 2xx (success message): extract JSON then `display_users()`  
  - Else print error message

- **delete_user**  
  - Prompt for `username` 
  - Validate that it is non-empty and contains no whitespace (to form a valid URL segment)
  - Build DELETE `/users/{username}` with admin cookies  
  - Print success or error message

- **logout_admin**  
  - GET `/logout` with admin cookies  
  - If 2xx(success message): free `cookies.admin` and clear vector  
  - Print success or error message

- **login**  
  - Prompt for `admin_username`, `username`, `password`  
  - Validate that none are empty and none contain spaces (to keep each credential token well-formed) 
  - Build JSON and POST to `/login_user` with admin cookies  
  - If 2xx(success message): extract cookies and store in `cookies.user[]`  
  - Print success or error message

- **get_access**  
  - GET `/library/access` with user cookies  
  - If 2xx(success message): extract `"token"` from JSON and store it in `jwt_token`  
  - Print success or error message

- **add_movie**  
  - Prompt `title, description, year, rating`  
   - Validate:  
    - `title` and `description` are non-empty (to ensure required data)  
    - `year` contains only digits (so it’s a valid integer)
    - `rating` is non-empty, contains only digits and at most one dot (using `validate_decimal()`) 
  - Build JSON and POST to `/movies` with cookies + `jwt_token`  
  - Print success or error message

- **get_movies**  
  - GET `/movies` with cookies + `jwt_token`  
  - If 2xx(success message): extract JSON and `display_movies_list()`  
  - Else print error message

- **get_movie**  
  - Prompt `id`  
  - Validate that it is non-empty and all characters are digits (to ensure a valid movie ID path)
  - GET `/movies/{id}` with cookies + `jwt_token`  
  - If 2xx: print raw JSON body  
  - Else print error message

- **update_movie**  
  - Prompt `id, title, year, description, rating`  
  - Validate:  
    - `id` and `year` are all digits (valid numeric IDs)  
    - `title` and `description` non-empty (required fields)  
    - `rating` decimal format (using `validate_decimal()`) 
  - Build JSON and PUT `/movies/{id}` with cookies and `jwt_token`  
  - Print success or error message

- **delete_movie**  
  - Prompt `id`  
  - Validate that it is non-empty and all digits (so the DELETE URL is valid) 
  - DELETE `/movies/{id}` with cookies and `jwt_token`  
  - Print success or error message

- **logout**  
  - GET `/logout_user` with user cookies  
  - If 2xx(success message): free `cookies.user` and clear vector  
  - Print success or error message

- **get_collections**  
  - GET `/collections` with cookies and `jwt_token`  
  - If 2xx(success message): extract JSON and `display_collections_list()`  
  - Else print error message

- **add_collection**  
  - Prompt `title, num_movies`  
  - Validate that `title` is non-empty (to name the collection) and `num_movies` is all digits (so we know how many IDs to read)  
  - Read each `movie_id` and validate it’s non-empty and all digits, then confirm existence via `movie_exists()`  
  - Create collection (POST `/collections`) and get new `coll_id`  
  - For each `movie_id`: POST `/collections/{coll_id}/movies`  
  - Print success or error message

- **get_collection**  
  - Prompt `id`  
  - Validate that it is non-empty and all digits (valid collection ID) 
  - GET `/collections/{id}` with cookies + `jwt_token`  
  - If 2xx(success msg): extract JSON and `display_collection_details()`  
  - Else print error message

- **delete_collection**  
  - Prompt `id`  
  - Validate that it is non-empty and all digits (so the DELETE URL is correct) 
  - DELETE `/collections/{id}` with cookies + `jwt_token`  
  - Print success or error message

- **add_movie_to_collection**  
  - Prompt `collection_id`, `movie_id`  
  - Validate both are non-empty and all digits (to form a valid POST URL and payload)
  - Build JSON `{ "id": movie_id }`  
  - POST `/collections/{collection_id}/movies` with cookies + `jwt_token`  
  - Print success or error message

- **delete_movie_from_collection**  
  - Prompt `collection_id`, `movie_id`  
  - Validate both are non-empty and all digits (to form a valid DELETE URL) 
  - DELETE `/collections/{collection_id}/movies/{movie_id}` with cookies + `jwt_token`  
  - Print success or error message

- **exit**  
  - Close socket and terminate program.  

---

## HTTP Message Construction (requests.cpp)

Each `compute_*_request()` does:

1. Allocate a zeroed buffer for headers (`calloc`).
2. Append the request line (`GET /path HTTP/1.1`).
3. Append standard headers: `Host`, `Content-Type` / `Content-Length` (for POST/PUT).
4. Serialize cookies into a single `Cookie:` header.
5. Optionally append `Authorization: Bearer <token>`.
6. Terminate headers with a blank line (`\r\n`).
7. For POST/PUT, append the body.

---

## Validation & Error Handling

- Input fields (IDs, year, rating) are validated before sending:
  - Numeric IDs use `std::all_of(..., ::isdigit)`.
  - Decimal values use a custom `validate_decimal()` (non-empty, only digits and number of dots less than 1).
- Server responses:
  - Status codes `2xx` -> success; everything else -> mapped to human-readable errors.
> Resource used: [here](https://umbraco.com/knowledge-base/http-status-codes/)
  - JSON bodies are extracted by finding the first `{` and validated with `nlohmann::json::accept()`.

---
