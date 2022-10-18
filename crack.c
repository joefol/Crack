#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <math.h>
#include <crypt.h> 

#define bufsize 100

int hashes = 0;

struct arg_data {
	pthread_t thread_id;
    	char start;
    	char end;
	char salt[bufsize];
	char hash[bufsize];
	int keysize;
};

int iterate(char* candidate, int length, int i){
	
    int result;
	
    if(i == length-1){
        if(candidate[i] == 'z'){
            candidate[i] = 'a';
            return 1;
        } 
		else{
            candidate[i]++;
            return 0;
        }
    }
    result = iterate(candidate, length, i+1);
	
    if(result == 1){
        if(candidate[i] == 'z'){
			candidate[i] = 'a';
            return 1;
        }
        candidate[i]++;
        return 0;
    }
}

void crack(struct crypt_data* data, int length, char start, int range, char* salt, char* hash){
	
    char candidate[length];
    for(int i=0; i<length; i++){
		candidate[i] = 'a';
	}
    candidate[0] = start;

    int maxIndex = pow(26, length-1)*range; //26^length = # of iterations, then times the range = total # of iterations
    for(int i=0; i<maxIndex; i++){
		
        char* result = crypt_r(candidate, salt, data);
		hashes++;
		
        if(strcmp(result, hash) == 0){
            printf("Password: %s\n", candidate);
	    printf("Hashes: %d\n", hashes);
            exit(0);
        }
        iterate(candidate, length, 0);
    }
}

void* thread_entry(void* args){
	
    struct arg_data* arg_ptr = (struct arg_data*) args;
	
    struct crypt_data data;
	data.initialized = 0;
	
    int range = arg_ptr->end - arg_ptr->start + 1;

    for(int i=1; i<=arg_ptr->keysize; i++){
		
		crack(&data, i, arg_ptr->start, range, arg_ptr->salt, arg_ptr->hash);
	}
	
	return NULL;
}

int main(int argc, char* argv[]){

	if(argc != 4){
        printf("Usage: <threads> <keysize> <target> -lpthread -lcrypt -lm\n");
		return -1;
	}
    
    char* hash = argv[3];
    int threads = atoi(argv[1]);
    int keySize = atoi(argv[2]);

    if (keySize < 1 || keySize > 8){
        printf("Error: Keysize must be a positive integer not greater than 8\n");
        return -1;
    }

    if (threads < 1){
		printf("Error: Number of threads must be greater than 0\n");
        return -1;
	}
	
	char salt[bufsize];
	memset(salt, '\0', bufsize);
	strncpy(salt, hash, 2);

    struct arg_data thread[threads];
    int x = 27/threads; //multi-thread

    thread[0].start = 'a';
	
    for(int i=0; i<threads; i++){
        thread[i].start = 'a' + x * i;

        if(threads == 1){
			thread[i].end = 'z';
		}
        else{
			thread[i].end = 'a' + x * (i+1)-1;
		}
    }
    
    for(int i=0; i<threads; i++){
		
		thread[i].keysize = keySize;
		snprintf(thread[i].hash, bufsize, "%s", hash);
		snprintf(thread[i].salt, bufsize, "%s", salt);
		
		int ret = pthread_create(&thread[i].thread_id, NULL, thread_entry, &thread[i]);
		if(ret != 0){
			printf("Error creating thread:");
			return -1;
		}
	}
	
    for(int i=0; i<threads; i++){
		pthread_join(thread[i].thread_id, NULL);
	}

	printf("hashes: %d\n", hashes);

	return 0;

}

