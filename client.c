#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include "helpers.h"
#include "requests.h"
#include "parson.h"

// function that checks if the username is empty or contains non-alphanumeric characters
int valid_username(char username[])
{
    // check if the username is empty
    if (!strlen(username))
        return 0;

    // check if the username contains non-alphanumerical letters
    for (size_t i = 0; i < strlen(username); i++) {
        if (!isalnum(username[i]))
            return 0;
    }

    return 1;
}

// function used for entering credentials
char *register_login_resp(int sockfd, char *url)
{
    char *message, *response, username[LINELEN], password[LINELEN];

    printf("username=");
    fgets(username, LINELEN, stdin);
    username[strlen(username) - 1] = '\0';

    printf("password=");
    fgets(password, LINELEN, stdin);
    password[strlen(password) - 1] = '\0';

    // check if password and username are valid
    if (!strlen(password) || strchr(password, ' ') != NULL || !valid_username(username)) {
        fprintf(stderr, "ERROR-Invalid username or password!\n");
        close_connection(sockfd);
        return NULL;
    }

    JSON_Value *value = json_value_init_object();
    JSON_Object *object = json_value_get_object(value);

    // prepare json with username and password
    json_object_set_string(object, "username", username);
    json_object_set_string(object, "password", password);
    char *str = json_serialize_to_string_pretty(value);
    char *body_data[] = {str};

    // send post request for register or login
    message = compute_post_request("34.246.184.49", url, "application/json", body_data, 1, NULL, 0, NULL);   
    send_to_server(sockfd, message);

    response = receive_from_server(sockfd);

    free(message);
    json_free_serialized_string(str);
    json_value_free(value);

    return response;  
}

// function for getting library access
char *get_library_access(int sockfd, char **cookies, int cookies_num)
{
    char *message, *response;
    char *session_token = calloc(LINELEN, sizeof(char));

    // prepare and send get request for library access
    message = compute_get_request("34.246.184.49", "/api/v1/tema/library/access", NULL, cookies, cookies_num, NULL);
    send_to_server(sockfd, message);

    response = receive_from_server(sockfd);

    // get content from the response
    char *content = strstr(response, "\r\n\r\n");
    content += 4;

    // check if there is a content
    if (content != NULL) {
        JSON_Value *resp_value = json_parse_string(content);
        JSON_Object *resp_object = json_value_get_object(resp_value);
        const char *content_str = json_object_get_string(resp_object, "error");

        // check if there is an error
        if (content_str != NULL) {
            fprintf(stderr, "ERROR-%s\n", content_str);
        } else {
            printf("200-OK-Acces succesfully granted!\n");

            // get the token
            const char *cookie_str = json_object_get_string(resp_object, "token");
            strcpy(session_token, cookie_str);
        }
        
        json_value_free(resp_value);
    } else {
        fprintf(stderr, "ERROR-No content received!\n");
    }

    free(message);
    free(response);

    return session_token;
}

// function for the get_books command
void get_books(int sockfd, char *session_token)
{
    char *message, *response;

    // prepare and send get request for get_books
    message = compute_get_request("34.246.184.49", "/api/v1/tema/library/books", NULL, NULL, 0, session_token);
    send_to_server(sockfd, message);

    response = receive_from_server(sockfd);

    // get content from the response
    char *content = strstr(response, "\r\n\r\n");
    content += 4;

    // check if there is a content
    if (content != NULL) {
        JSON_Value *resp_value = json_parse_string(content);
        JSON_Object *resp_object = json_value_get_object(resp_value);
        const char *content_str = json_object_get_string(resp_object, "error");

        // check if there is an error
        if (content_str != NULL) {
            fprintf(stderr, "ERROR-%s\n", content_str);
        } else {
             char *list = json_serialize_to_string_pretty(resp_value);
             printf("%s\n", list);
        }

        json_value_free(resp_value);
    } else {
        fprintf(stderr, "ERROR-No content received!\n");
    }     

    free(message);
    free(response);
}

// function for the get_book command
void get_book(int sockfd, char *session_token)
{
    char *message, *response;
    char id[LINELEN];

    printf("id=");
    fgets(id, LINELEN, stdin);
    id[strlen(id) - 1] = '\0';

    char *end = NULL;
    strtol(id, &end, 10);
    errno = 0;

    // check if the id is a valid number
    if (end == id || *end != '\0' || errno == ERANGE) {
        fprintf(stderr, "ERROR-Invalid id!\n");
        return;
    }

    // add the id to the url
    char url[] = "/api/v1/tema/library/books/";
    strcat(url, id);

    // prepare and send get request for the book with the specified id
    message = compute_get_request("34.246.184.49", url, NULL, NULL, 0, session_token);
    send_to_server(sockfd, message);

    response = receive_from_server(sockfd);

    // get the content from the response
    char *content = strstr(response, "\r\n\r\n");
    content += 4;

    // check if there is a content
    if (content != NULL) {
        JSON_Value *resp_value = json_parse_string(content);
        JSON_Object *resp_object = json_value_get_object(resp_value);
        const char *content_str = json_object_get_string(resp_object, "error");

        // check if there is an error
        if (content_str != NULL) {
            fprintf(stderr, "ERROR-%s\n", content_str);
        } else {
            char *book_str = json_serialize_to_string_pretty(resp_value);
            printf("%s\n", book_str);
        }

        json_value_free(resp_value);
    } else {
        fprintf(stderr, "ERROR-No content received!\n");
    }

    free(message);
    free(response);
}

// function for adding a book
void add_book(int sockfd, char *session_token)
{
    char *message, *response;
    char title[LINELEN], author[LINELEN], genre[LINELEN], publisher[LINELEN], page_count[LINELEN];

    printf("title=");
    fgets(title, LINELEN, stdin);
    title[strlen(title) - 1] = '\0';

    printf("author=");
    fgets(author, LINELEN, stdin);
    author[strlen(author) - 1] = '\0';

    printf("genre=");
    fgets(genre, LINELEN, stdin);
    genre[strlen(genre) - 1] = '\0';

    printf("publisher=");
    fgets(publisher, LINELEN, stdin);
    publisher[strlen(publisher) - 1] = '\0';

    printf("page_count=");
    fgets(page_count, LINELEN, stdin);
    page_count[strlen(page_count) - 1] = '\0';

    char *end = NULL;
    long page_count_long = strtol(page_count, &end, 10);
    errno = 0;

    // check if all fields were completed
    if (!strlen(title) || !strlen(author) || !strlen(genre) || !strlen(publisher)) {
        fprintf(stderr, "ERROR-All fields must be completed!\n");    
        return;
    }

    // check if page_count is a valid number
    if (end == page_count || *end != '\0' || errno == ERANGE) {
        fprintf(stderr, "ERROR-Invalid page_count!\n");
        return;
    }

    // prepare json with book details
    JSON_Value *new_book_value = json_value_init_object();
    JSON_Object *new_book_object = json_value_get_object(new_book_value);

    json_object_set_string(new_book_object, "title", title);
    json_object_set_string(new_book_object, "author", author);
    json_object_set_string(new_book_object, "genre", genre);
    json_object_set_number(new_book_object, "page_count", page_count_long);
    json_object_set_string(new_book_object, "publisher", publisher);
    char *new_book_str = json_serialize_to_string_pretty(new_book_value);
    char *body_data[] = {new_book_str};

    // prepare and send post request for adding book
    message = compute_post_request("34.246.184.49", "/api/v1/tema/library/books", "application/json", body_data, 1, NULL, 0, session_token);
    send_to_server(sockfd, message);

    response = receive_from_server(sockfd);

    // get the content from the response    
    char *content = strstr(response, "\r\n\r\n");
    content += 4;

    // check if there is a content
    if (content != NULL) {
        JSON_Value *resp_value = json_parse_string(content);
        JSON_Object *resp_object = json_value_get_object(resp_value);
        const char *content_str = json_object_get_string(resp_object, "error");

        // check if there is an error
        if (content_str != NULL)
            fprintf(stderr, "ERROR-%s\n", content_str);
        else
            printf("200-OK-Book added successfully!\n");
        
        json_value_free(resp_value);
    } else {
        fprintf(stderr, "ERROR-No content received!\n");
    }

    free(message);
    free(response);
    json_free_serialized_string(new_book_str);
    json_value_free(new_book_value);
}

// function for deleting a book
void delete_book(int sockfd, char *session_token)
{
    char *message, *response;
    char id[LINELEN];

    printf("id=");
    fgets(id, LINELEN, stdin);
    id[strlen(id) - 1] = '\0';

    char *end = NULL;
    long id_long = strtol(id, &end, 10);
    errno = 0;

    // check if the id is a valid number
    if (end == id || *end != '\0' || errno == ERANGE) {
        fprintf(stderr, "ERROR-Invalid id!\n");
        return;
    }

    // add the id to the url
    char url[] = "/api/v1/tema/library/books/";
    strcat(url, id);

    // prepare delete request for deleting the book
    message = compute_delete_request("34.246.184.49", url, NULL, NULL, 0, session_token);
    send_to_server(sockfd, message);

    response = receive_from_server(sockfd);

    // get the content from the response
    char *content = strstr(response, "\r\n\r\n");
    content += 4;

    // check if there is a content
    if (content != NULL) {
        JSON_Value *resp_value = json_parse_string(content);
        JSON_Object *resp_object = json_value_get_object(resp_value);
        const char *content_str = json_object_get_string(resp_object, "error");

        // check if there is an error
        if (content_str != NULL)
            fprintf(stderr, "ERROR-%s\n", content_str);
        else
            printf("200-OK-Book with id %ld deleted successfully!\n", id_long);
        
        json_value_free(resp_value);
    } else {
        fprintf(stderr, "ERROR-No content received!\n");
    }

    free(message);
    free(response);
}

// function for logging out
char *logout(int sockfd, char **cookies, int cookies_num)
{
    char *message, *response = NULL;

    // prepare and send get request for logging out
    message = compute_get_request("34.246.184.49", "/api/v1/tema/auth/logout", NULL, cookies, cookies_num, NULL);
    send_to_server(sockfd, message);

    response = receive_from_server(sockfd);
    free(message);

    return response;    
}

int main(int argc, char *argv[])
{
    char *response;
    int sockfd;
    char cmd[BUFLEN];
    char **cookies = NULL;
    int cookies_num = 0;
    char *session_token = NULL;
    
    while (1) {
        sockfd = open_connection("34.246.184.49", 8080, AF_INET, SOCK_STREAM, 0);
        fgets(cmd, BUFLEN, stdin);
        cmd[strlen(cmd) - 1] = '\0';

        if (strcmp(cmd, "register") == 0) {
            response = register_login_resp(sockfd, "/api/v1/tema/auth/register");

            // if response is NULL, it means that the username or password were invalid
            if (response == NULL)
                continue;

            // get content from the response
            char *content = strstr(response, "\r\n\r\n");
            content += 4;

            // check if there is a content
            if (content != NULL) {
                JSON_Value *resp_value = json_parse_string(content);
                JSON_Object *resp_object = json_value_get_object(resp_value);
                const char *content_str = json_object_get_string(resp_object, "error");

                // check if there is an error
                if (content_str != NULL)
                    fprintf(stderr, "ERROR-%s\n", content_str);
                else
                    printf("200-OK-User succesfully registered!\n");

                json_value_free(resp_value);
            } else {
                fprintf(stderr, "ERROR-No content received!\n");
            }

            free(response);            
        } else if (strcmp(cmd, "login") == 0) {
            response = register_login_resp(sockfd, "/api/v1/tema/auth/login");

            // if response is NULL, it means that the username or password were invalid
            if (response == NULL)
                continue;

            // get content from the response
            char *content = strstr(response, "\r\n\r\n");
            content += 4;           

            // check if there is a content
            if (content != NULL) {
                JSON_Value *resp_value = json_parse_string(content);
                JSON_Object *resp_object = json_value_get_object(resp_value);
                const char *content_str = json_object_get_string(resp_object, "error");

                // check if there is an error
                if (content_str != NULL) {
                    fprintf(stderr, "ERROR-%s\n", content_str);
                } else {
                    printf("200-OK-User succesfully logged in!\n");

                    // if there are any cookies from previous login free the memory
                    for(int i = 0; i < cookies_num; i++)
                        free(cookies[i]);

                    if (cookies != NULL) {
                        free(cookies);
                        cookies = NULL;
                    }

                    cookies_num = 0;

                    if (session_token != NULL) {
                        free(session_token);
                        session_token = NULL;
                    }       

                    // get the cookies line
                    char *cookie_start = strstr(response, "Set-Cookie: ");                    
                    cookie_start += 12;
                    char *cookie_end = strstr(cookie_start, "\r\n");
                    char *cookie_content = strndup(cookie_start, cookie_end - cookie_start);

                    // separe the cookies and store them in cookies
                    char *cookie = strtok(cookie_content, "; ");
                    cookies = calloc(4096, sizeof(char));

                    while (cookie != NULL) {
                        cookies[cookies_num++] = strdup(cookie);
                        cookie = strtok(NULL, "; ");
                    }

                    free(cookie_content);
                }

                json_value_free(resp_value);
            } else {
                fprintf(stderr, "ERROR-No content received!\n");
            }

            free(response);
        } else if (strcmp(cmd, "enter_library") == 0) {
            // free the session_token if it wasn't freed previously
            if (session_token != NULL) {
                free(session_token);
                session_token = NULL;
            }

            session_token = get_library_access(sockfd, cookies, cookies_num);
        } else if (strcmp(cmd, "get_books") == 0) {
            get_books(sockfd, session_token);
        } else if (strcmp(cmd, "get_book") == 0) {
            get_book(sockfd, session_token);
        } else if (strcmp(cmd, "add_book") == 0) {
            add_book(sockfd, session_token);   
        } else if (strcmp(cmd, "delete_book") == 0) {
            delete_book(sockfd, session_token);
        } else if (strcmp(cmd, "logout") == 0) {
            response = logout(sockfd, cookies, cookies_num);

            // get content from the response            
            char *content = strstr(response, "\r\n\r\n");
            content += 4;

            // check if there is a content
            if (content != NULL) {
                JSON_Value *resp_value = json_parse_string(content);
                JSON_Object *resp_object = json_value_get_object(resp_value);
                const char *content_str = json_object_get_string(resp_object, "error");

                // check if there is an error
                if (content_str != NULL) {
                    fprintf(stderr, "ERROR-%s\n", content_str);
                } else {
                    // if there are cookies saved free the memory
                    for(int i = 0; i < cookies_num; i++)
                        free(cookies[i]);

                    if (cookies != NULL) {
                        free(cookies);
                        cookies = NULL;
                    }

                    cookies_num = 0;

                    if (session_token != NULL) {
                        free(session_token);
                        session_token = NULL;
                    }
                    
                    printf("200-OK-User succesfully logged out!\n");
                }

                json_value_free(resp_value);
            } else {
                fprintf(stderr, "ERROR-No content received!\n");
            }

            free(response);
        } else if (strcmp(cmd, "exit") == 0) {
            // check if there is allocated memory and if there is free it
            for(int i = 0; i < cookies_num; i++)
                free(cookies[i]);

            if (cookies != NULL) {
                free(cookies);
                cookies = NULL;
            }

            cookies_num = 0;

            if (session_token != NULL) {
                free(session_token);
                session_token = NULL;
            }

            close_connection(sockfd);

            // exit from the loop
            break;       
        } else {
            fprintf(stderr, "ERROR-Unknown command!\n");
        }
        
        close_connection(sockfd);
    }

    return 0;
}
