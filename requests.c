#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <stdio.h>
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"

char *compute_get_request(char *host, char *url, char *query_params, char *auth_value,
                            char **cookies, int cookies_count)
{
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));

    // write the method name, URL, request params (if any) and protocol type
    if (query_params != NULL) {
        sprintf(line, "GET %s?%s HTTP/1.1", url, query_params);
    } else {
        sprintf(line, "GET %s HTTP/1.1", url);
    }

    compute_message(message, line);

    // add the host
    // Clear line
    clear_line(line);
    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    if (auth_value != NULL) {
        clear_line(line);
        sprintf(line, "Authorization: %s", auth_value);
        compute_message(message, line);
    }
    
    clear_line(line);
    sprintf(line, "Cookie: ");

    // add headers and/or cookies, according to the protocol format
    if (cookies != NULL) {
       for (int i = 0; i < cookies_count - 1; i++) {
            sprintf(line + strlen(line), "%s", cookies[i]);
            sprintf(line + strlen(line), "; ");
       }

       sprintf(line + strlen(line), "%s", cookies[cookies_count - 1]);
       compute_message(message, line);
    }

    // add final new line
    compute_message(message, "");

    free(line);

    return message;
}

char *compute_post_request(char *host, char *url, char* content_type, char *auth_value,
                            char **body_data, int body_data_fields_count, char** cookies,
                            int cookies_count)
{
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));
    char *body_data_buffer = calloc(LINELEN, sizeof(char));

    // write the method name, URL and protocol type
    sprintf(line, "POST %s HTTP/1.1", url);
    compute_message(message, line);
    
    // add the host
    clear_line(line);
    sprintf(line, "Host: %s", host);
    /* add necessary headers (Content-Type and Content-Length are mandatory)
            in order to write Content-Length you must first compute the message size
    */
    compute_message(message, line);

    clear_line(line);
    if (auth_value != NULL) {
        clear_line(line);
        sprintf(line, "Authorization: %s", auth_value);
        compute_message(message, line);
    }

    clear_line(line);
    sprintf(line, "Content-Type: %s", content_type);
    compute_message(message, line);
   
    // Compute the message size
    unsigned int message_size = 0;

    message_size += strlen(body_data[0]);
    for (int i = 1; i < body_data_fields_count; i++) {
        message_size += strlen(body_data[i]);
        message_size ++;    // '&'
    }

    clear_line(line);
    sprintf(line, "Content-Length: %d", message_size);
    compute_message(message, line);

    clear_line(line);

    // add cookies
    sprintf(line, "Cookie: ");
    if (cookies != NULL) {
        for (int i = 0; i < cookies_count - 1; i++) {
            sprintf(line + strlen(line), "%s", cookies[i]);
            sprintf(line + strlen(line), "; ");
       }

        sprintf(line + strlen(line), "%s", cookies[cookies_count - 1]);
        compute_message(message, line);
    }

    // dd new line at end of header
    compute_message(message, "");

    // add the actual payload data
    for (int i = 0 ; i < body_data_fields_count - 1; i++) {
        sprintf(body_data_buffer, "%s&", body_data[i]);
    }

    sprintf(body_data_buffer + strlen(body_data_buffer),
     "%s", body_data[body_data_fields_count - 1]);
    compute_message(message, body_data_buffer);

    free(line);
    free(body_data_buffer);
    return message;
}

char *compute_delete_request(char *host, char *url, int book_id, char *auth_value)
{
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));

    sprintf(line, "DELETE %s/%d HTTP/1.1", url, book_id);
    compute_message(message, line);

    // add the host
    clear_line(line);
    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    if (auth_value != NULL) {
        clear_line(line);
        sprintf(line, "Authorization: %s", auth_value);
        compute_message(message, line);
    }
    
    // add final new line
    compute_message(message, "");

    free(line);
    return message;
}