/*
* Protocoale de comunicatii
* Laborator 9 - HTTP
* requests.hpp
* https://pcom.pages.upb.ro/labs/lab9/http_req.html
*/
#ifndef _REQUESTS_
#define _REQUESTS_

char *compute_get_request(const char *host,
						  const char *url,
						  const char *query_params,
						  const std::vector<char *> &cookies,
						  int cookies_count,
						  const char *token);

char *compute_post_request(const char *host,
						   const char *url,
						   const char *content_type,
						   char **body_data,
						   int body_data_fields_count,
						   const std::vector<char *> &cookies,
						   int cookies_count,
						   const char *token);

char *compute_delete_request(const char *host,
							 const char *url,
							 const std::vector<char *> &cookies,
							 int cookies_count,
							 const char *jwt_token);

char *compute_put_request(const char *host,
						  const char *url,
						  const char *content_type,
						  const char *body_data,
						  const std::vector<char *> &cookies,
						  int cookies_count,
						  const char *token);

#endif
