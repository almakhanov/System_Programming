#include <stdio.h>
#include <unistd.h>

int main(){

    int k = 0;
    while(1){
	     k++;
	     printf("print %d\n", k);
	     sleep(1);
    }

    return 0;
}
