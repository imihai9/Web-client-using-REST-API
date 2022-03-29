// Partial source: PC - lab10 skel

#ifndef _REQUESTS_
#define _REQUESTS_

// computes and returns a GET request string (auth, query_params
// and cookies can be set to NULL if not needed)
char *compute_get_request(char *host, char *url, char *query_params, char *auth_value,
							char **cookies, int cookies_count);

// computes and returns a POST request string (auth and cookies can be NULL if not needed)
char *compute_post_request(char *host, char *url, char* content_type, char *auth_value,
							char **body_data, int body_data_fields_count, char** cookies,
							int cookies_count);

// computes and returns a DELETE request string (auth can be NULL if not needed)
char *compute_delete_request(char *host, char *url, int book_id, char *auth_value);
#endif
