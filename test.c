#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "parson.h"
#define STRING_LEN 20

/*	data_types	= 0 for strings
				= 1 for numbers	*/
void JSON_serialization (char **fields, char **values, uint8_t *data_types, int len) {
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    char *serialized_string = NULL;

    for (int i = 0; i < len; i++) {
    	if (data_types[i] == 0)
    		json_object_set_string(root_object, fields[i], values[i]);
    	else
    		json_object_set_number(root_object, fields[i], atoi(values[i]));
    }
    
    serialized_string = json_serialize_to_string_pretty(root_value);
    puts(serialized_string);
}

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

int main ()
{
	char *string = strdup("HTTP/1.1 201 Created\
");
	short int srv_resp = get_status_code(string);
	printf("%hd\n", srv_resp);

	//char **strings[2];
	/*char **fields = (char**)malloc(3 * sizeof(char*));
	char **values = (char**)malloc(3 * sizeof(char*));
	uint8_t *data_types = malloc(2);

	fields[0] = strdup("username");
	values[0] = strdup("testing");
	data_types[0] = 0;
	fields[1] = strdup("password");
	values[1] = strdup("123");
	data_types[1] = 1;
	fields[2] = strdup("sdsdsd");
	values[2] = strdup("sdsds");
	data_types[2] = 0;
	JSON_serialization(fields, values, data_types, 3);*/
}