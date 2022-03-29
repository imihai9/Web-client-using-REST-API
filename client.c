// Starting point: my implementation of PC - lab10

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

#define SRV_IP "34.118.48.238"
#define SRV_PORT 8080
#define SRV_HOST SRV_IP ":8080"
#define MAX_CMD_LEN 20
#define MAX_VAL_LEN 256
#define MAX_BOOK_ID_LEN 10
#define MAX_URL_SIZE 40
int sockfd;

// Returns the status code from a HTML server reply
short int get_status_code (char *_srv_resp) {
    if (_srv_resp == NULL)
        return -1;

    char *srv_resp = strdup(_srv_resp);
    char *p = strtok(srv_resp, " ");
    p = strtok(NULL, " ");

    short int status_code;
    if (p == NULL) 
        status_code = -1;
    else 
        status_code = atoi(p);
    
    free(srv_resp);
    return status_code;
}

// Extracts the session ID cookie from a HTML server reply
char* extract_sid_cookie (char *message) {
    char *start = strstr(message, "connect.sid=");
    char *stop = strstr(start, ";");
    unsigned int sid_size = stop - start;

    char *sid = (char*) calloc(sid_size + 1, sizeof(char));
    strncpy(sid, start, sid_size);
    return sid;
}
 
char *gen_authorization_field (const char *jwt_token) {
    if (jwt_token == NULL)
        return NULL;

    char *auth_value = (char*)malloc(8 + strlen(jwt_token)); // "Bearer " + token + '\0'
    strcat(auth_value, "Bearer ");
    strcat(auth_value, jwt_token);

    return auth_value;
}

void send_to_server_wrapper(char *message) {
    sockfd = open_connection(SRV_IP, SRV_PORT, AF_INET, SOCK_STREAM, 0);
    send_to_server(sockfd, message);
}

// Reads [username, password]
// Returns the JSON-formatted string containing [username, password]
// Also returns the username through the 'username' param
char *JSON_client_auth (char **_username) {
    // 2 fields: username, password
    *_username = (char*)malloc(MAX_VAL_LEN);
    char *username = *_username;
    char *password = (char*)malloc(MAX_VAL_LEN);

    fprintf(stdout, "username=");
    fgets(username, MAX_VAL_LEN - 1, stdin);
    fprintf(stdout, "password=");
    fgets(password, MAX_VAL_LEN - 1, stdin);

    username[strlen(username) - 1] = '\0';  // delete trailing newlines
    password[strlen(password) - 1] = '\0';

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    char *serialized_string = NULL;
    json_object_set_string(root_object, "username", username);
    json_object_set_string(root_object, "password", password);
    serialized_string = json_serialize_to_string_pretty(root_value);

    free(password);
    json_value_free(root_value);

    return serialized_string;
}

// Reads client registration data [username, password]
// [POST] Registers the user
void client_register () {
    char *username;
    char *JSON_auth_string = JSON_client_auth(&username);
    char *message = compute_post_request(SRV_HOST, "/api/v1/tema/auth/register",
        "application/json", NULL, &JSON_auth_string, 1, NULL, 0);

    free(JSON_auth_string);

    send_to_server_wrapper(message);
    
    char *response = receive_from_server(sockfd);
    short int status_code = get_status_code(response);
    const char *error_msg;

    switch(status_code) {
        case 201:
            fprintf(stdout, "[SUCCESS] The user %s was registered.\n", username);
            break;
        case 429:
            fprintf(stdout, "[FAIL] Too many requests.\n");
            break;
        case 400:
            error_msg = basic_extract_error_json_response(response);
            if (error_msg) {
                fprintf(stdout, "[FAIL] %s\n", error_msg);
            } else {
                fprintf(stdout, "[FAIL] Bad request.\n");
            }
            break;
        default:
            fprintf(stdout, "[FAIL] Undefined status code.\n");
    }
}

// Reads client login data
// [POST] Authenticates the user
// Returns the session ID cookie, if login was successful
char *client_login () {
    char *username;
    char *JSON_auth_string = JSON_client_auth(&username);
    char *message = compute_post_request(SRV_HOST, "/api/v1/tema/auth/login",
        "application/json", NULL, &JSON_auth_string, 1, NULL, 0);

    free(JSON_auth_string);

    send_to_server_wrapper(message);
    
    char *response = receive_from_server(sockfd);

    short int status_code = get_status_code(response);
    char *sid_cookie;
    const char *error_msg;

    switch(status_code) {
        case 200:    // code 200
            sid_cookie = extract_sid_cookie(response);
            if (sid_cookie) {
                fprintf(stdout, "[SUCCESS] The user %s was logged in.\n", username);
                return sid_cookie;
            }
            break;
        case 400:
            error_msg = basic_extract_error_json_response(response);
            if (error_msg) {
                fprintf(stdout, "[FAIL] %s\n", error_msg);
            } else {
                fprintf(stdout, "[FAIL] Bad request.\n");
            }
            break;
        default:
            fprintf(stdout, "[FAIL] Undefined status code.\n");
    }

    return NULL;
}

// [GET] Requests library access for current client
// Returns the JWT Token
const char *client_enter_lib (char *sid_cookie) {
    char *message = compute_get_request(SRV_HOST, "/api/v1/tema/library/access", NULL, NULL,
                            &sid_cookie, 1);
    
    send_to_server_wrapper(message);
    char *response = receive_from_server(sockfd);
    char *token_cookie;
    const char *error_msg;
    short int status_code = get_status_code(response);

    switch(status_code) {
        case 200:    // OK
            token_cookie = basic_extract_json_response(response);
            if (!token_cookie)
                break;

            JSON_Value *token_json_value = json_parse_string(token_cookie);
            JSON_Object *token_json_object = json_value_get_object(token_json_value);
            const char *token_string = json_object_get_string(token_json_object, "token");

            fprintf(stdout, "[SUCCESS] Entered the library.\n");

            return token_string;
            break;
        case 401: // error - you are not logged in!
            error_msg = basic_extract_error_json_response(response);
            if (error_msg) {
                fprintf(stdout, "[FAIL] %s\n", error_msg);
                break;
            }
        default:
            fprintf(stdout, "[FAIL] Undefined status code.\n");
    }

    return NULL;
}

// [GET] Requests a list of the books in user's library
// Prints the list
void client_get_all_books (const char *jwt_token) { 
    char *auth_value = gen_authorization_field(jwt_token);
    char *message = compute_get_request(SRV_HOST, "/api/v1/tema/library/books", NULL, auth_value,
                            NULL, 0);
    if (auth_value != NULL) // Can be NULL! (if no jwt token is present)
        free(auth_value);

    send_to_server_wrapper(message);
    char *response = receive_from_server(sockfd);

    const char *books_response_string, *error_msg;
    int cnt_books;
    JSON_Value *books_json_value;
    JSON_Array *books_json_array;
    JSON_Object *book_json;

    short int status_code = get_status_code(response);

    switch(status_code) {
        case 200:    // OK
            books_response_string = basic_extract_json_array(response);
            if (!books_response_string)
                break;

            books_json_value = json_parse_string(books_response_string);
            books_json_array = json_value_get_array(books_json_value);
            cnt_books = json_array_get_count(books_json_array);

            if (cnt_books == 0) {
                fprintf(stdout, "[SUCCESS] No books in your library.\n");
            } else {
                fprintf(stdout, "[SUCCESS] The following books are in your library:\n");
                printf("%-10.10s %s\n", "ID", "Title");
                for (int i = 0; i < cnt_books; i++) {
                    book_json = json_array_get_object(books_json_array, i);
                    printf("%-10.0f %s\n",
                        json_object_get_number(book_json, "id"),
                        json_object_get_string(book_json, "title"));
                }
                json_value_free(books_json_value);
            }
            break;
        case 403:   // Auth header is missing
            fprintf(stdout, "[FAIL] Not authorized!\n");
            break;
        case 401:
        case 500:   // Internal server error (probably wrong token)
            error_msg = basic_extract_error_json_response(response);
            if (error_msg) {
                fprintf(stdout, "[FAIL] %s\n", error_msg);
                break;
            }
        default:
            fprintf(stdout, "[FAIL] Undefined status code.\n");
    }
}

// [GET] Requests details about a book in the user's library (by ID)
// Prints the details, if the book exists
void client_get_book (const char *jwt_token) {
    int book_id;
    fprintf(stdout, "id=");
    char *book_id_string = (char*)malloc(MAX_BOOK_ID_LEN); // 10 = max digits in an ID;

    fgets(book_id_string, MAX_BOOK_ID_LEN, stdin);
    book_id = atoi(book_id_string);
    free(book_id_string);

    char *auth_value = gen_authorization_field(jwt_token);
    char *url = (char*)malloc(MAX_URL_SIZE);
    sprintf(url, "%s%d", "/api/v1/tema/library/books/", book_id);
    char *message = compute_get_request(SRV_HOST, url, NULL, auth_value, NULL, 0);

    if (auth_value != NULL)
        free(auth_value);

    send_to_server_wrapper(message);
    char *response = receive_from_server(sockfd);

    char *book_details_response_string;
    const char *error_msg;
    JSON_Value *book_details_json_value;
    JSON_Array *book_details_json_array;
    JSON_Object *book_json;

    short int status_code = get_status_code(response);

    switch(status_code) {
        case 200:    // OK
            book_details_response_string = basic_extract_json_array(response);
            if (!book_details_response_string)
                break;

            book_details_json_value = json_parse_string(book_details_response_string);
            book_details_json_array = json_value_get_array(book_details_json_value);

            fprintf(stdout, "[SUCCESS] Details: \n");
            book_json = json_array_get_object(book_details_json_array, 0);
            printf("%-12.12s %s\n", "Title: ", json_object_get_string(book_json, "title"));
            printf("%-12.12s %s\n", "Author: ", json_object_get_string(book_json, "author"));
            printf("%-12.12s %s\n", "Publisher: ", json_object_get_string(book_json, "publisher"));
            printf("%-12.12s %s\n", "Genre: ", json_object_get_string(book_json, "genre"));
            printf("%-12.12s %.0f\n", "Page count: ", json_object_get_number(book_json, "page_count"));
            json_value_free(book_details_json_value);
            break;
        case 403:   // Auth header is missing
            fprintf(stdout, "[FAIL] Not authorized!\n");
            break;
        case 404:   // Not found
        case 500:   // Internal server error (probably wrong token)
            error_msg = basic_extract_error_json_response(response);
            if (error_msg) {
                fprintf(stdout, "[FAIL] %s\n", error_msg);
                break;
            }
        default:
            fprintf(stdout, "[FAIL] Undefined status code.\n");
    }

}

char *JSON_client_read_book () {
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    char *serialized_string = NULL;

    char *read_string = (char*)malloc(MAX_VAL_LEN);
    int read_num;

    fprintf(stdout, "title=");
    fgets(read_string, MAX_VAL_LEN - 1, stdin);
    read_string[strlen(read_string) - 1] = '\0';
    json_object_set_string(root_object, "title", read_string);

    fprintf(stdout, "author=");
    fgets(read_string, MAX_VAL_LEN - 1, stdin);
    read_string[strlen(read_string) - 1] = '\0';
    json_object_set_string(root_object, "author", read_string);

    fprintf(stdout, "genre=");
    fgets(read_string, MAX_VAL_LEN - 1, stdin);
    read_string[strlen(read_string) - 1] = '\0';
    json_object_set_string(root_object, "genre", read_string);

    fprintf(stdout, "page_count=");
    fgets(read_string, MAX_VAL_LEN - 1, stdin);
    read_string[strlen(read_string) - 1] = '\0';
    read_num = atoi(read_string);
    json_object_set_number(root_object, "page_count", read_num);

    fprintf(stdout, "publisher=");
    fgets(read_string, MAX_VAL_LEN - 1, stdin);
    read_string[strlen(read_string) - 1] = '\0';
    json_object_set_string(root_object, "publisher", read_string);

    serialized_string = json_serialize_to_string_pretty(root_value);
    free(read_string);
    json_value_free(root_value);

    return serialized_string;
}

void client_add_book (const char *jwt_token) {
    char *auth_value = gen_authorization_field(jwt_token);
    char *JSON_book = JSON_client_read_book();
    char *message = compute_post_request(SRV_HOST, "/api/v1/tema/library/books",
        "application/json", auth_value, &JSON_book, 1, NULL, 0);
    if (auth_value != NULL)
        free(auth_value);

    send_to_server_wrapper(message);
    
    char *response = receive_from_server(sockfd);
    short int status_code = get_status_code(response);
    const char *error_msg;

    switch(status_code) {
        case 200:
            fprintf(stdout, "[SUCCESS] The book was added to your library.\n");
            break;
        case 403:   // Auth header is missing
            fprintf(stdout, "[FAIL] Not authorized!\n");
            break;
        case 429:
            fprintf(stdout, "[FAIL] Too many requests.\n");
            break;
        case 400:
            error_msg = basic_extract_error_json_response(response);
            if (error_msg) {
                fprintf(stdout, "[FAIL] %s\n", error_msg);
            } else {
                fprintf(stdout, "[FAIL] Bad request.\n");
            }
            break;
        case 500:   // Probably token error
            error_msg = basic_extract_error_json_response(response);
            if (error_msg) {
                fprintf(stdout, "[FAIL] %s\n", error_msg);
                break;
            }
        default:
            fprintf(stdout, "[FAIL] Undefined status code.\n");
    }
}

void client_del_book (const char *jwt_token) {
    char *auth_value = gen_authorization_field(jwt_token);
    char *book_id_string = (char*)malloc(MAX_BOOK_ID_LEN);

    fprintf(stdout, "id=");
    fgets(book_id_string, MAX_BOOK_ID_LEN, stdin);
    int book_id = atoi(book_id_string);
    free(book_id_string);

    char *message = compute_delete_request(SRV_HOST, "/api/v1/tema/library/books", book_id, auth_value);

    if (auth_value != NULL)
        free(auth_value);

    send_to_server_wrapper(message);
    
    char *response = receive_from_server(sockfd);
    short int status_code = get_status_code(response);
    const char *error_msg;

    switch(status_code) {
        case 200:
            fprintf(stdout, "[SUCCESS] The book was deleted.\n");
            break;
        case 403:   // Auth header is missing
            fprintf(stdout, "[FAIL] Not authorized!\n");
            break;
        case 404:
            fprintf(stdout, "[FAIL] No book was deleted!\n");
            break;
        case 429:
            fprintf(stdout, "[FAIL] Too many requests.\n");
            break;
        case 400:
            error_msg = basic_extract_error_json_response(response);
            if (error_msg) {
                fprintf(stdout, "[FAIL] %s\n", error_msg);
            } else {
                fprintf(stdout, "[FAIL] Bad request.\n");
            }
            break;
        case 500:   // Probably token error
            error_msg = basic_extract_error_json_response(response);
            if (error_msg) {
                fprintf(stdout, "[FAIL] %s\n", error_msg);
                break;
            }
        default:
            fprintf(stdout, "[FAIL] Undefined status code.\n");
    }
}

void client_logout (char *sid_cookie) {
    char *message = compute_get_request(SRV_HOST, "/api/v1/tema/auth/logout", NULL, NULL, &sid_cookie, 1);
    send_to_server_wrapper(message);
    char *response = receive_from_server(sockfd);

    short int status_code = get_status_code(response);
    const char *error_msg;

    switch(status_code) {
        case 200:
            fprintf(stdout, "[SUCCESS] You were logged out.\n");
            break;
        case 429:
            fprintf(stdout, "[FAIL] Too many requests.\n");
            break;
        case 400:
            error_msg = basic_extract_error_json_response(response);
            if (error_msg) {
                fprintf(stdout, "[FAIL] %s\n", error_msg);
            } else {
                fprintf(stdout, "[FAIL] Bad request.\n");
            }
            break;
        default:
            fprintf(stdout, "[FAIL] Undefined status code.\n");
    }
}

// Reads client cmd, returns it
// Returns JSON_payload param if applicable
uint8_t parse_client_cmd () {
    char *cmd, *sid_cookie;
    const char *jwt_token = NULL;
    cmd = (char*)malloc(MAX_CMD_LEN);

    while (1) {
        fgets(cmd, MAX_CMD_LEN - 1, stdin);
        cmd[strlen(cmd) - 1] = '\0';    // delete trailing '\n'

        if (strcmp(cmd, "register") == 0) {
            client_register();
        } else if (strcmp(cmd, "login") == 0) {
            // If another login session was active => delete
            // SID cookie and JWT Auth token.
            if (sid_cookie != NULL) {
                free(sid_cookie);
                sid_cookie = NULL;
                jwt_token = NULL;
            }
            sid_cookie = client_login();
        } else if (strcmp(cmd, "enter_library") == 0) {
            jwt_token = client_enter_lib(sid_cookie);
        } else if (strcmp(cmd, "get_books") == 0) {
            client_get_all_books(jwt_token);    
        } else if (strcmp(cmd, "get_book") == 0) {
            client_get_book(jwt_token);
        } else if (strcmp(cmd, "add_book") == 0) {
            client_add_book(jwt_token);
        } else if (strcmp(cmd, "delete_book") == 0) {
            client_del_book(jwt_token);
        } else if (strcmp(cmd, "logout") == 0) {
            client_logout(sid_cookie);
            if (sid_cookie != NULL) {
                free(sid_cookie);
                sid_cookie = NULL;
            }
            jwt_token = NULL;
        } else if (strcmp(cmd, "exit") == 0) {
            if (sid_cookie != NULL) {
                free(sid_cookie);
                sid_cookie = NULL;
            }
            jwt_token = NULL;
            return 1;
        } else {
            fprintf(stdout, "[FAIL] Unknown command.\n");
        }

        fprintf(stdout, "\n");
    }

    return 0;
}

int main(int argc, char *argv[]) {
    sockfd = open_connection(SRV_IP, SRV_PORT, AF_INET, SOCK_STREAM, 0);

    // Open the TCP connection with the server
    int ret = parse_client_cmd();
    if (ret != 0) {
        close_connection(sockfd);
        return 0;
    }
    
    return 0;
}
